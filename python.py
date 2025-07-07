#!/usr/bin/env python3

import os
import requests
import logging
from datetime import datetime
from azure.identity import ClientSecretCredential
from azure.mgmt.resource import SubscriptionClient, ResourceManagementClient
from azure.mgmt.appcontainers import ContainerAppsAPIClient
from azure.core.exceptions import HttpResponseError
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

# === Load Environment Variables ===
# Note: No need for dotenv as GitHub Actions will provide these as env vars

# Azure Authentication
AZURE_CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
AZURE_CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")
AZURE_TENANT_ID = os.getenv("AZURE_TENANT_ID")

# Email Configuration
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
FROM_EMAIL = os.getenv("EMAIL")  # Your verified SendGrid sender email
TO_EMAILS = os.getenv("TO_EMAIL")  # Comma-separated list of recipients

# Monitoring settings
MAX_RETRIES = 3  # Number of retries for HTTP checks
RETRY_DELAY = 2  # Delay between retries (in seconds)
TIMEOUT = 10  # HTTP timeout in seconds

# === Setup Logging ===
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('container_apps_monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# === Email Function using SendGrid ===
def send_summary_email(report_body: str, html_report: str = None):
    """Send email with monitoring results using SendGrid"""
    recipients = [email.strip() for email in TO_EMAILS.split(",") if email.strip()]
    if not recipients:
        logger.warning("No email recipients configured")
        return

    subject = f"[Pangea] Azure Container App Health Alert - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    
    try:
        message = Mail(
            from_email=FROM_EMAIL,
            to_emails=recipients,
            subject=subject,
            plain_text_content=report_body,
            html_content=html_report
        )

        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
        
        if response.status_code == 202:
            logger.info(f"Email sent successfully to {recipients}")
        else:
            logger.error(f"Failed to send email. Status code: {response.status_code}")
    except Exception as e:
        logger.error(f"Failed to send email: {str(e)}")

# === Health Check with Retry ===
def check_endpoint_health(url: str) -> dict:
    """Check endpoint health with retry logic"""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.get(
                url,
                timeout=TIMEOUT,
                headers={'User-Agent': 'PangeaContainerAppMonitor/1.0'}
            )
            
            return {
                'healthy': response.status_code == 200,
                'status_code': response.status_code,
                'response_time': response.elapsed.total_seconds(),
                'error': None
            }
        except requests.exceptions.RequestException as e:
            if attempt == MAX_RETRIES:
                return {
                    'healthy': False,
                    'status_code': None,
                    'response_time': None,
                    'error': str(e)
                }
            time.sleep(RETRY_DELAY)
    
    return {
        'healthy': False,
        'status_code': None,
        'response_time': None,
        'error': 'All retries failed'
    }

# === Generate HTML Report ===
def generate_html_report(report_data: list) -> str:
    """Generate HTML version of the report"""
    if not report_data:
        return ""
        
    html = f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1 {{ color: #333; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
            th {{ background-color: #f2f2f2; }}
            .unhealthy {{ color: red; }}
            .warning {{ color: orange; }}
        </style>
    </head>
    <body>
        <h1>Azure Container App Health Alert</h1>
        <p>Dear Pangea Production Team,</p>
        <p>The following container apps are experiencing issues:</p>
        <table>
            <tr>
                <th>Subscription</th>
                <th>Resource Group</th>
                <th>App Name</th>
                <th>URL</th>
                <th>Status</th>
                <th>Response Time</th>
                <th>Details</th>
            </tr>
    """
    
    for item in report_data:
        status_class = "warning" if item['status_code'] else "unhealthy"
        status_text = f"HTTP {item['status_code']}" if item['status_code'] else "Connection Error"
        
        html += f"""
            <tr>
                <td>{item['subscription']}</td>
                <td>{item['resource_group']}</td>
                <td>{item['app_name']}</td>
                <td><a href="{item['url']}">{item['url']}</a></td>
                <td class="{status_class}">{status_text}</td>
                <td>{item['response_time'] or 'N/A'}s</td>
                <td>{item['error'] or 'N/A'}</td>
            </tr>
        """
    
    html += """
        </table>
        <p>Please investigate these services immediately.</p>
        <p>Regards,<br>Monitoring System<br>Pangea Platform</p>
    </body>
    </html>
    """
    return html

# === Main Monitoring Function ===
def check_all_container_apps():
    """Check health of all container apps"""
    # Authenticate using Service Principal
    credential = ClientSecretCredential(
        client_id=AZURE_CLIENT_ID,
        client_secret=AZURE_CLIENT_SECRET,
        tenant_id=AZURE_TENANT_ID
    )
    
    sub_client = SubscriptionClient(credential)
    failed_apps = []
    
    for sub in sub_client.subscriptions.list():
        sub_id = sub.subscription_id
        sub_name = sub.display_name
        logger.info(f"Checking subscription: {sub_name}")
        
        try:
            rg_client = ResourceManagementClient(credential, sub_id)
            container_client = ContainerAppsAPIClient(credential, sub_id)
            
            for rg in rg_client.resource_groups.list():
                rg_name = rg.name
                logger.info(f"Checking resource group: {rg_name}")
                
                try:
                    apps = container_client.container_apps.list_by_resource_group(rg_name)
                    
                    for app in apps:
                        app_name = app.name
                        try:
                            details = container_client.container_apps.get(rg_name, app_name)
                            fqdn = getattr(details.configuration.ingress, 'fqdn', None)
                            
                            if not fqdn:
                                logger.info(f"Skipping {app_name} - no public endpoint")
                                continue
                                
                            url = f"https://{fqdn}"
                            logger.info(f"Checking {app_name} at {url}")
                            
                            health = check_endpoint_health(url)
                            
                            if not health['healthy']:
                                failed_apps.append({
                                    'subscription': sub_name,
                                    'resource_group': rg_name,
                                    'app_name': app_name,
                                    'url': url,
                                    'status_code': health['status_code'],
                                    'response_time': health['response_time'],
                                    'error': health['error']
                                })
                                logger.warning(f"Unhealthy: {app_name} - {health['error'] or health['status_code']}")
                                
                        except HttpResponseError as e:
                            logger.error(f"Error checking {app_name}: {str(e)}")
                            failed_apps.append({
                                'subscription': sub_name,
                                'resource_group': rg_name,
                                'app_name': app_name,
                                'url': 'N/A',
                                'status_code': None,
                                'response_time': None,
                                'error': str(e)
                            })
                            
                except Exception as e:
                    logger.error(f"Error listing apps in {rg_name}: {str(e)}")
                    continue
                    
        except Exception as e:
            logger.error(f"Error processing subscription {sub_name}: {str(e)}")
            continue
    
    # Only send report if there are failed apps
    if failed_apps:
        # Generate plain text report
        plain_report = f"Dear Pangea Production Team,\n\n"
        plain_report += f"The following container apps are experiencing issues:\n\n"
        plain_report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        for item in failed_apps:
            status = f"HTTP {item['status_code']}" if item['status_code'] else f"ERROR: {item['error']}"
            plain_report += (
                f"Subscription: {item['subscription']}\n"
                f"Resource Group: {item['resource_group']}\n"
                f"App Name: {item['app_name']}\n"
                f"URL: {item['url']}\n"
                f"Status: {status}\n"
                f"Response Time: {item['response_time'] or 'N/A'}s\n"
                f"Details: {item['error'] or 'N/A'}\n"
                f"{'-'*50}\n"
            )
        
        plain_report += "\nPlease investigate these services immediately.\n\nRegards,\nMonitoring System\nPangea Platform"
        
        # Generate HTML report
        html_report = generate_html_report(failed_apps)
        
        send_summary_email(plain_report, html_report)
    else:
        logger.info("All container apps are healthy - no alerts sent")

if __name__ == "__main__":
    logger.info("Starting Azure Container Apps health check")
    check_all_container_apps()
    logger.info("Health check completed")
