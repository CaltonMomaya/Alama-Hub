import requests
import re
from bs4 import BeautifulSoup
import time
from typing import Dict, Optional, Tuple

class TSCVerifier:
    """Verifies teacher registration status with TSC Kenya"""
    
    def __init__(self):
        self.base_url = "https://tsconline.tsc.go.ke"
        self.status_url = f"{self.base_url}/register/registration-status"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0',
        })
        
    def get_csrf_token(self) -> Optional[str]:
        """Extract CSRF token from the form page"""
        try:
            response = self.session.get(self.status_url, timeout=10)
            response.raise_for_status()
            
            # Parse HTML for CSRF token
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Look for CSRF token in common locations
            csrf_token = None
            
            # Method 1: Check meta tag
            meta_token = soup.find('meta', {'name': 'csrf-token'})
            if meta_token:
                csrf_token = meta_token.get('content')
            
            # Method 2: Check input field
            if not csrf_token:
                input_token = soup.find('input', {'name': '_token'})
                if input_token:
                    csrf_token = input_token.get('value')
            
            return csrf_token
            
        except requests.exceptions.RequestException as e:
            print(f"Error fetching CSRF token: {e}")
            return None
    
    def verify_teacher(self, id_number: str, id_type: str = "ID") -> Dict:
        """
        Verify teacher registration status with TSC
        
        Args:
            id_number: National ID or Passport number
            id_type: "ID" for National ID, "PASSPORT" for Passport
        
        Returns:
            Dictionary with verification results
        """
        result = {
            'valid': False,
            'status': None,
            'tsc_number': None,
            'full_name': None,
            'error': None,
            'raw_response': None
        }
        
        if not id_number or len(id_number.strip()) < 5:
            result['error'] = "Invalid ID number provided"
            return result
        
        try:
            # Get CSRF token first
            csrf_token = self.get_csrf_token()
            if not csrf_token:
                result['error'] = "Could not access TSC verification portal"
                return result
            
            # Prepare form data
            form_data = {
                '_token': csrf_token,
                'identification_type': 'national_id' if id_type.upper() == "ID" else 'passport_number',
                'identification_number': id_number.strip(),
                'search': ''
            }
            
            # Submit verification request
            response = self.session.post(
                self.status_url,
                data=form_data,
                headers={
                    'Referer': self.status_url,
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Origin': self.base_url
                },
                timeout=15
            )
            
            response.raise_for_status()
            result['raw_response'] = response.text
            
            # Parse the response
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Look for success/error messages
            alert_success = soup.find('div', class_='alert-success')
            alert_danger = soup.find('div', class_='alert-danger')
            
            if alert_danger:
                # Error message found
                error_text = alert_danger.get_text(strip=True)
                result['error'] = error_text
                
                if "invalid" in error_text.lower():
                    result['status'] = "INVALID_ID"
                elif "not found" in error_text.lower():
                    result['status'] = "NOT_FOUND"
                else:
                    result['status'] = "ERROR"
            
            elif alert_success:
                # Success - teacher found
                success_text = alert_success.get_text(strip=True)
                result['status'] = "REGISTERED"
                result['valid'] = True
                
                # Extract TSC number and name using regex patterns
                tsc_pattern = r'TSN/(\d{5,})/'  # Pattern for TSC number
                name_pattern = r'([A-Z\s]+)(?=\s+TSN/)'  # Pattern for teacher name
                
                # Find TSC number
                tsc_match = re.search(tsc_pattern, success_text)
                if tsc_match:
                    result['tsc_number'] = tsc_match.group(1)
                
                # Find teacher name
                name_match = re.search(name_pattern, success_text)
                if name_match:
                    result['full_name'] = name_match.group(1).strip()
                
                # Alternative: Parse table data if available
                table = soup.find('table', class_='table')
                if table:
                    rows = table.find_all('tr')
                    for row in rows:
                        cells = row.find_all('td')
                        if len(cells) >= 2:
                            header = cells[0].get_text(strip=True).lower()
                            value = cells[1].get_text(strip=True)
                            
                            if 'tsc' in header and not result['tsc_number']:
                                result['tsc_number'] = value
                            elif 'name' in header and not result['full_name']:
                                result['full_name'] = value
            
            else:
                # Couldn't parse the response
                result['error'] = "Could not parse verification response"
                result['status'] = "PARSING_ERROR"
            
            # Add delay to be respectful to the server
            time.sleep(1)
            
        except requests.exceptions.Timeout:
            result['error'] = "TSC portal timeout - please try again later"
            result['status'] = "TIMEOUT"
        except requests.exceptions.ConnectionError:
            result['error'] = "Cannot connect to TSC portal"
            result['status'] = "CONNECTION_ERROR"
        except requests.exceptions.RequestException as e:
            result['error'] = f"Network error: {str(e)}"
            result['status'] = "NETWORK_ERROR"
        except Exception as e:
            result['error'] = f"Unexpected error: {str(e)}"
            result['status'] = "UNKNOWN_ERROR"
        
        return result


# FastAPI Web Service Integration
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import Optional
import uvicorn

app = FastAPI(title="TSC Verification API", version="1.0.0")

class VerificationRequest(BaseModel):
    id_number: str = Field(..., min_length=5, max_length=20, description="National ID or Passport number")
    id_type: str = Field(default="ID", description="ID type: 'ID' or 'PASSPORT'")
    tsc_number: Optional[str] = Field(None, description="TSC number to cross-check (optional)")

class VerificationResponse(BaseModel):
    success: bool
    message: str
    tsc_number: Optional[str]
    full_name: Optional[str]
    status: str
    error: Optional[str]

def get_verifier():
    return TSCVerifier()

@app.post("/verify-tsc", response_model=VerificationResponse)
async def verify_tsc(
    request: VerificationRequest,
    verifier: TSCVerifier = Depends(get_verifier)
):
    """Verify TSC registration status"""
    
    # Basic validation
    if not request.id_number:
        raise HTTPException(status_code=400, detail="ID number is required")
    
    # Verify with TSC portal
    result = verifier.verify_teacher(request.id_number, request.id_type)
    
    # Prepare response
    if result['valid']:
        # Optional: Cross-check with provided TSC number
        if request.tsc_number and result['tsc_number']:
            if request.tsc_number != result['tsc_number']:
                return VerificationResponse(
                    success=False,
                    message="TSC number mismatch",
                    tsc_number=result['tsc_number'],
                    full_name=result['full_name'],
                    status="TSC_MISMATCH",
                    error=f"Provided TSC {request.tsc_number} doesn't match registered TSC {result['tsc_number']}"
                )
        
        return VerificationResponse(
            success=True,
            message="Teacher is registered with TSC",
            tsc_number=result['tsc_number'],
            full_name=result['full_name'],
            status=result['status'],
            error=None
        )
    else:
        return VerificationResponse(
            success=False,
            message="Teacher not found or not registered",
            tsc_number=None,
            full_name=None,
            status=result['status'],
            error=result['error']
        )

# Rate limiting middleware (simplified)
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.get("/health")
@limiter.limit("10/minute")
async def health_check():
    return {"status": "healthy", "service": "tsc-verification"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)