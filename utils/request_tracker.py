"""
Request Tracker for AWS API Calls

Tracks all AWS API requests made during data collection, including success/failure
status, error details, and timing information. This data is used by tests to
differentiate between:
- Resource doesn't exist (valid scenario)
- Permission denied (IAM/role issue)
- API error (AWS service issue)
- Other errors
"""

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict, field


@dataclass
class RequestError:
    """Details about an API request error"""
    type: str  # Error type (e.g., "UnauthorizedOperation", "AccessDenied")
    code: str  # Error code
    message: str  # Error message
    operation: str  # AWS operation that failed


@dataclass
class APIRequest:
    """Details about a single AWS API request"""
    timestamp: str  # ISO 8601 timestamp
    service: str  # AWS service (e.g., "ec2", "elbv2", "iam")
    operation: str  # Operation name (e.g., "describe_instances")
    success: bool  # True if request succeeded
    duration_ms: int  # Request duration in milliseconds
    response_code: Optional[int] = None  # HTTP response code
    error: Optional[Dict[str, str]] = None  # Error details if failed
    parameters: Optional[Dict[str, Any]] = None  # Request parameters (optional)
    output_file: Optional[str] = None  # File where response was saved


@dataclass
class CollectionMetadata:
    """Metadata about the data collection session"""
    cluster_id: str
    infra_id: str
    collection_start: str  # ISO 8601 timestamp
    collection_end: Optional[str] = None  # ISO 8601 timestamp
    aws_region: str = "unknown"
    aws_account_id: str = "unknown"


@dataclass
class RequestSummary:
    """Summary statistics for all requests"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    permission_errors: int = 0
    not_found_errors: int = 0
    throttling_errors: int = 0
    service_errors: int = 0
    other_errors: int = 0


class RequestTracker:
    """Tracks AWS API requests and saves results to JSON"""

    def __init__(self, cluster_id: str, infra_id: str, output_dir: Path):
        """
        Initialize request tracker.

        Args:
            cluster_id: Cluster ID
            infra_id: Infrastructure ID
            output_dir: Directory to save request log
        """
        self.metadata = CollectionMetadata(
            cluster_id=cluster_id,
            infra_id=infra_id,
            collection_start=datetime.utcnow().isoformat() + 'Z'
        )
        self.requests: List[APIRequest] = []
        self.output_dir = Path(output_dir)
        self.output_file = self.output_dir / f"{cluster_id}_api_requests.json"

        # Summary statistics
        self.summary = RequestSummary()

    def track_request(
        self,
        service: str,
        operation: str,
        success: bool,
        duration_ms: int,
        response_code: Optional[int] = None,
        error: Optional[Exception] = None,
        parameters: Optional[Dict[str, Any]] = None,
        output_file: Optional[str] = None
    ) -> None:
        """
        Track an AWS API request.

        Args:
            service: AWS service name (e.g., "ec2", "elbv2")
            operation: Operation name (e.g., "describe_instances")
            success: True if request succeeded
            duration_ms: Request duration in milliseconds
            response_code: HTTP response code
            error: Exception if request failed
            parameters: Request parameters (optional, for debugging)
            output_file: File where response was saved (if applicable)
        """
        # Parse error details
        error_dict = None
        if error:
            error_dict = self._parse_error(error, operation)

        # Create request record
        request = APIRequest(
            timestamp=datetime.utcnow().isoformat() + 'Z',
            service=service,
            operation=operation,
            success=success,
            duration_ms=duration_ms,
            response_code=response_code,
            error=error_dict,
            parameters=self._sanitize_parameters(parameters),
            output_file=output_file
        )

        # Add to requests list
        self.requests.append(request)

        # Update summary statistics
        self._update_summary(request)

    def _parse_error(self, error: Exception, operation: str) -> Dict[str, str]:
        """Parse exception into error dictionary"""
        error_type = type(error).__name__
        error_code = error_type
        error_message = str(error)

        # Try to extract AWS-specific error details
        if hasattr(error, 'response'):
            response = error.response
            if isinstance(response, dict):
                error_info = response.get('Error', {})
                error_code = error_info.get('Code', error_code)
                error_message = error_info.get('Message', error_message)
                error_type = error_info.get('Type', error_type)

        return {
            'type': error_type,
            'code': error_code,
            'message': error_message,
            'operation': operation
        }

    def _sanitize_parameters(self, parameters: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Sanitize request parameters to remove sensitive data.

        Args:
            parameters: Request parameters

        Returns:
            Sanitized parameters or None
        """
        if not parameters:
            return None

        # For now, just limit the size of parameter data
        # In the future, could redact sensitive fields
        sanitized = {}
        for key, value in parameters.items():
            if isinstance(value, (str, int, bool, type(None))):
                sanitized[key] = value
            elif isinstance(value, list):
                # Limit list size
                if len(value) <= 10:
                    sanitized[key] = value
                else:
                    sanitized[key] = f"<list with {len(value)} items>"
            else:
                sanitized[key] = str(type(value).__name__)

        return sanitized

    def _update_summary(self, request: APIRequest) -> None:
        """Update summary statistics based on request"""
        self.summary.total_requests += 1

        if request.success:
            self.summary.successful_requests += 1
        else:
            self.summary.failed_requests += 1

            # Categorize error type
            if request.error:
                error_code = request.error.get('code', '').lower()
                error_type = request.error.get('type', '').lower()

                if any(perm in error_code or perm in error_type for perm in
                       ['unauthorized', 'accessdenied', 'forbidden', 'permission']):
                    self.summary.permission_errors += 1
                elif 'notfound' in error_code or 'doesnotexist' in error_code:
                    self.summary.not_found_errors += 1
                elif 'throttl' in error_code or 'ratelimit' in error_code:
                    self.summary.throttling_errors += 1
                elif 'service' in error_type or 'internal' in error_type:
                    self.summary.service_errors += 1
                else:
                    self.summary.other_errors += 1

    def save(self) -> None:
        """Save request log to JSON file"""
        # Set collection end time
        self.metadata.collection_end = datetime.utcnow().isoformat() + 'Z'

        # Build output structure
        output = {
            'collection_metadata': asdict(self.metadata),
            'requests': [asdict(req) for req in self.requests],
            'summary': asdict(self.summary)
        }

        # Save to file
        self.output_dir.mkdir(parents=True, exist_ok=True)
        with open(self.output_file, 'w') as f:
            json.dump(output, f, indent=2, default=str)

    def get_failed_requests(self, service: Optional[str] = None) -> List[APIRequest]:
        """
        Get all failed requests, optionally filtered by service.

        Args:
            service: Filter by service name (e.g., "ec2")

        Returns:
            List of failed requests
        """
        failed = [req for req in self.requests if not req.success]

        if service:
            failed = [req for req in failed if req.service == service]

        return failed

    def get_permission_errors(self) -> List[APIRequest]:
        """Get all requests that failed due to permission issues"""
        permission_errors = []

        for req in self.requests:
            if not req.success and req.error:
                error_code = req.error.get('code', '').lower()
                error_type = req.error.get('type', '').lower()

                if any(perm in error_code or perm in error_type for perm in
                       ['unauthorized', 'accessdenied', 'forbidden', 'permission']):
                    permission_errors.append(req)

        return permission_errors

    def get_requests_for_operation(self, operation: str) -> List[APIRequest]:
        """
        Get all requests for a specific operation.

        Args:
            operation: Operation name (e.g., "describe_instances")

        Returns:
            List of requests for that operation
        """
        return [req for req in self.requests if req.operation == operation]

    def __str__(self) -> str:
        """String representation of request tracker summary"""
        return (
            f"Request Tracker Summary:\n"
            f"  Total Requests: {self.summary.total_requests}\n"
            f"  Successful: {self.summary.successful_requests}\n"
            f"  Failed: {self.summary.failed_requests}\n"
            f"    Permission Errors: {self.summary.permission_errors}\n"
            f"    Not Found Errors: {self.summary.not_found_errors}\n"
            f"    Throttling Errors: {self.summary.throttling_errors}\n"
            f"    Service Errors: {self.summary.service_errors}\n"
            f"    Other Errors: {self.summary.other_errors}\n"
        )
