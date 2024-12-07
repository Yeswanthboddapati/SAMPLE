import re
import csv
from collections import defaultdict

# Constants
FAILED_LOGIN_THRESHOLD = 10  # Default threshold for failed login attempts

def parse_log_file(file_path):
    # Data structures to store counts
    ip_count = defaultdict(int)
    endpoint_count = defaultdict(int)
    failed_logins = defaultdict(int)

    # Regular expression patterns
    ip_pattern = r'(\d+\.\d+\.\d+\.\d+)'
    endpoint_pattern = r'"(?:GET|POST|PUT|DELETE)\s(/[^"]*)'
    failed_login_pattern = r'HTTP/\d\.\d"\s401'
    
    try:
        with open(file_path, 'r') as log_file:
            for line in log_file:
                # Extract IP address
                ip_match = re.search(ip_pattern, line)
                if ip_match:
                    ip_address = ip_match.group(1)
                    ip_count[ip_address] += 1
                
                # Extract endpoint (path)
                endpoint_match = re.search(endpoint_pattern, line)
                if endpoint_match:
                    endpoint = endpoint_match.group(1)
                    endpoint_count[endpoint] += 1
                
                # Detect failed login attempts (status code 401)
                if re.search(failed_login_pattern, line):
                    ip_match = re.search(ip_pattern, line)
                    if ip_match:
                        failed_ip = ip_match.group(1)
                        failed_logins[failed_ip] += 1
    except FileNotFoundError:
        print(f"Error: The file {file_path} was not found.")
        return None, None, None

    return ip_count, endpoint_count, failed_logins

def display_results(ip_count, endpoint_count, failed_logins):
    # Display Requests per IP Address
    print(f"{'IP Address':<20} {'Request Count'}")
    print("="*40)
    for ip, count in sorted(ip_count.items(), key=lambda item: item[1], reverse=True):
        print(f"{ip:<20} {count}")
    
    # Display Most Frequently Accessed Endpoint
    most_accessed_endpoint = max(endpoint_count.items(), key=lambda item: item[1], default=None)
    if most_accessed_endpoint:
        endpoint, count = most_accessed_endpoint
        print(f"\nMost Frequently Accessed Endpoint:\n{endpoint} (Accessed {count} times)")

    # Display Suspicious Activity (Failed Login Attempts)
    print("\nSuspicious Activity Detected:")
    print(f"{'IP Address':<20} {'Failed Login Attempts'}")
    print("="*40)
    for ip, failed_count in sorted(failed_logins.items(), key=lambda item: item[1], reverse=True):
        if failed_count > FAILED_LOGIN_THRESHOLD:
            print(f"{ip:<20} {failed_count}")

def save_results_to_csv(ip_count, endpoint_count, failed_logins):
    # Save to CSV
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # Write Requests per IP
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in sorted(ip_count.items(), key=lambda item: item[1], reverse=True):
            writer.writerow([ip, count])
        
        # Write Most Accessed Endpoint
        most_accessed_endpoint = max(endpoint_count.items(), key=lambda item: item[1], default=None)
        if most_accessed_endpoint:
            endpoint, count = most_accessed_endpoint
            writer.writerow([])
            writer.writerow(['Most Accessed Endpoint', 'Access Count'])
            writer.writerow([endpoint, count])
        
        # Write Suspicious Activity (Failed Login Attempts)
        writer.writerow([])
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, failed_count in sorted(failed_logins.items(), key=lambda item: item[1], reverse=True):
            if failed_count > FAILED_LOGIN_THRESHOLD:
                writer.writerow([ip, failed_count])

if __name__ == "__main__":
    # Path to the log file
    log_file_path = 'sample.log'
    
    # Parse the log file
    ip_count, endpoint_count, failed_logins = parse_log_file(log_file_path)
    
    if ip_count is None:
        print("Error processing the log file.")
    else:
        # Display results
        display_results(ip_count, endpoint_count, failed_logins)
        
        # Save results to CSV
        save_results_to_csv(ip_count, endpoint_count, failed_logins)
