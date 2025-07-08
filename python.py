#!/usr/bin/env python3

import os
import requests
import logging
import time
from datetime import datetime
from azure.identity import ClientSecretCredential
from azure.mgmt.resource import SubscriptionClient, ResourceManagementClient
from azure.mgmt.appcontainers import ContainerAppsAPIClient
from azure.core.exceptions import HttpResponseError
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

# === Load Environment Variables ===
AZURE_CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
AZURE_CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")
AZURE_TENANT_ID = os.getenv("AZURE_TENANT_ID")
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
FROM_EMAIL = os.getenv("EMAIL")
TO_EMAILS = os.getenv("TO_EMAIL")

# Monitoring settings
MAX_RETRIES = 3
RETRY_DELAY = 2
TIMEOUT = 10
HEALTHY_STATUS_CODES = {200, 201, 202, 204}

# === Logging ===
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('container_apps_monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# === Email Sending ===
def send_summary_email(report_body: str, html_report: str = None):
    if not SENDGRID_API_KEY or not FROM_EMAIL or not TO_EMAILS:
        logger.warning("Email configuration incomplete - skipping email send")
        return
    recipients = [email.strip() for email in TO_EMAILS.split(",") if email.strip()]
    if not recipients:
        logger.warning("No email recipients configured")
        return

    subject = f"Azure Container App Health Alert - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
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

# === HTTP Health Check ===
def check_endpoint_health(url: str) -> dict:
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.get(
                url,
                timeout=TIMEOUT,
                headers={'User-Agent': 'AzureContainerAppMonitor/1.0'},
                allow_redirects=False
            )
            is_healthy = response.status_code in HEALTHY_STATUS_CODES
            return {
                'healthy': is_healthy,
                'status_code': response.status_code,
                'response_time': response.elapsed.total_seconds(),
                'error': None if is_healthy else f"HTTP {response.status_code}"
            }
        except requests.exceptions.SSLError as e:
            return {
                'healthy': False,
                'status_code': None,
                'response_time': None,
                'error': f"SSL Error: {str(e)}"
            }
        except requests.exceptions.ConnectionError as e:
            return {
                'healthy': False,
                'status_code': None,
                'response_time': None,
                'error': f"Connection Error: {str(e)}"
            }
        except requests.exceptions.Timeout as e:
            if attempt == MAX_RETRIES:
                return {
                    'healthy': False,
                    'status_code': None,
                    'response_time': None,
                    'error': "Timeout - Service may be overloaded or down"
                }
            time.sleep(RETRY_DELAY)
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
        'error': "Retries exhausted"
    }

# === Check for Container Issues ===
def check_container_issues(container_client, rg_name, app_name):
    try:
        app = container_client.container_apps.get(rg_name, app_name)
        issues = []
        
        # Check for image issues
        for container in app.properties.template.containers:
            if not container.image:
                issues.append("Missing container image")
            elif "error" in container.image.lower():
                issues.append(f"Invalid image: {container.image}")
        
        # Check provisioning state
        if app.properties.provisioning_state and "failed" in app.properties.provisioning_state.lower():
            issues.append(f"Provisioning failed: {app.properties.provisioning_state}")
            
        # Check running state
        if hasattr(app.properties, 'running') and not app.properties.running:
            issues.append("Container is stopped")
            
        return ", ".join(issues) if issues else None
        
    except Exception as e:
        logger.error(f"Error checking container issues for {app_name}: {str(e)}")
        return None

# === HTML Report ===
def generate_html_report(report_data: list) -> str:
    if not report_data:
        return ""

    html = f"""
    <html>
    <head>
        <style>
    body { font-family: Arial, sans-serif; margin: 20px; color: black; }
    h1 { color: black; }
    .header { margin-bottom: 20px; }
    table { border-collapse: collapse; width: 100%; margin-bottom: 20px; color: black; }
    th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
    th { background-color: #f2f2f2; color: black; }
    a { color: blue; text-decoration: none; }
    .status { color: red; font-weight: bold; }
    .footer { margin-top: 20px; color: black; }
</style>

    </head>
    <body>
        <div class="header">
            <h1>Azure Container App Health Report</h1>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <p>Dear Pangea Production Team,</p>
        <p>The following container apps require your attention:</p>
        
        <table>
            <tr>
                <th>Subscription</th>
                <th>Resource Group</th>
                <th>App Name</th>
                <th>URL</th>
                <th>Status</th>
                <th>Response Time</th>
                <th>Details</th>
                <th>Container Issues</th>
            </tr>
    """
    
    for item in report_data:
        status_class = "error"
        if item['status_code'] == 404:
            status_class = "warning"
        elif "timeout" in item['error'].lower():
            status_class = "warning"
            
        html += f"""
            <tr class="{status_class}">
                <td>{item['subscription']}</td>
                <td>{item['resource_group']}</td>
                <td>{item['app_name']}</td>
                <td><a href="{item['url']}">{item['url']}</a></td>
                <td>{item['status_code'] or 'Error'}</td>
                <td>{item['response_time'] or 'N/A'}s</td>
                <td>{item['error'] or 'N/A'}</td>
                <td>{item.get('container_issues', 'None detected')}</td>
            </tr>
        """
    
    html += """
        </table>
        
        <div class="footer">
            <p>Please investigate these issues promptly.</p>
            <p>Regards,<br>Production Team - Pangea</p>

        </div>
    </body>
    </html>
    """
    return html

# === Main Function ===
def check_all_container_apps():
    if not all([AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID]):
        logger.error("Missing Azure credentials")
        return

    credential = ClientSecretCredential(
        client_id=AZURE_CLIENT_ID,
        client_secret=AZURE_CLIENT_SECRET,
        tenant_id=AZURE_TENANT_ID
    )

    failed_apps = []
    sub_client = SubscriptionClient(credential)

    for sub in sub_client.subscriptions.list():
        sub_id = sub.subscription_id
        sub_name = sub.display_name
        logger.info(f"Checking subscription: {sub_name}")

        container_client = ContainerAppsAPIClient(credential, sub_id)
        rg_client = ResourceManagementClient(credential, sub_id)

        for rg in rg_client.resource_groups.list():
            rg_name = rg.name
            logger.info(f"Checking resource group: {rg_name}")

            for app in container_client.container_apps.list_by_resource_group(rg_name):
                app_name = app.name
                try:
                    details = container_client.container_apps.get(rg_name, app_name)
                    fqdn = getattr(details.configuration.ingress, 'fqdn', None)
                    if not fqdn:
                        logger.info(f"Skipping {app_name} - no public endpoint")
                        continue

                    url = f"https://{fqdn}"
                    health = check_endpoint_health(url)
                    container_issues = check_container_issues(container_client, rg_name, app_name)

                    if not health['healthy'] or container_issues:
                        failed_apps.append({
                            'subscription': sub_name,
                            'resource_group': rg_name,
                            'app_name': app_name,
                            'url': url,
                            'status_code': health['status_code'],
                            'response_time': health['response_time'],
                            'error': health['error'],
                            'container_issues': container_issues
                        })
                        logger.warning(f"App issue detected: {app_name} - {health['error'] or container_issues}")

                except HttpResponseError as e:
                    logger.error(f"Error checking {app_name}: {str(e)}")
                    failed_apps.append({
                        'subscription': sub_name,
                        'resource_group': rg_name,
                        'app_name': app_name,
                        'url': 'N/A',
                        'status_code': None,
                        'response_time': None,
                        'error': str(e),
                        'container_issues': "Unable to check container issues"
                    })

    if failed_apps:
        plain_report = f"""Azure Container App Health Alert

Dear Pangea Production Team,

The following container apps require your attention:

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

"""
        for item in failed_apps:
            plain_report += f"""
Subscription: {item['subscription']}
Resource Group: {item['resource_group']}
App Name: {item['app_name']}
URL: {item['url']}
Status: {item['status_code'] or 'Error'}
Response Time: {item.get('response_time', 'N/A')}s
Error Details: {item.get('error', 'N/A')}
Container Issues: {item.get('container_issues', 'None detected')}
{'='*50}
"""
        plain_report += "\nPlease investigate these issues promptly.\n\nRegards,\nAzure Container Apps Monitoring System"
        
        html_report = generate_html_report(failed_apps)
        send_summary_email(plain_report, html_report)
    else:
        logger.info("All container apps are healthy.")

if __name__ == "__main__":
    logger.info("Starting Azure Container App health check")
    check_all_container_apps()
    logger.info("Health check completed")
