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

# === HTML Report ===
def generate_html_report(report_data: list) -> str:
    if not report_data:
        return ""

    html = f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial; margin: 20px; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ padding: 8px; border: 1px solid #ddd; }}
            th {{ background-color: #f2f2f2; }}
            .unhealthy {{ color: red; }}
            .stopped {{ color: #990000; background-color: #ffeeee; }}
        </style>
    </head>
    <body>
        <h1>Azure Container App Health Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <table>
            <tr>
                <th>Subscription</th>
                <th>Resource Group</th>
                <th>App Name</th>
                <th>URL</th>
                <th>Status</th>
                <th>Azure State</th>
                <th>Response Time</th>
                <th>Details</th>
            </tr>
    """
    for item in report_data:
        status_class = "stopped" if item['azure_state'] != "Running" else "unhealthy"
        status_text = f"HTTP {item['status_code']}" if item['status_code'] else item['error']
        html += f"""
            <tr>
                <td>{item['subscription']}</td>
                <td>{item['resource_group']}</td>
                <td>{item['app_name']}</td>
                <td><a href="{item['url']}">{item['url']}</a></td>
                <td class="{status_class}">{status_text}</td>
                <td class="{status_class}">{item['azure_state']}</td>
                <td>{item['response_time'] or 'N/A'}s</td>
                <td>{item['error'] or 'N/A'}</td>
            </tr>
        """
    html += "</table><p>Regards,<br>Monitoring System</p></body></html>"
    return html

# === Get App Provisioning State ===
def get_container_app_state(container_client, rg_name, app_name):
    try:
        revisions = container_client.container_apps_revisions.list(rg_name, app_name)
        for rev in revisions:
            if rev.properties.active:
                return 'Running'
        return 'NoActiveRevision'
    except Exception as e:
        logger.exception(f"Error fetching revision state for {app_name}: {str(e)}")
        return 'ERROR'




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

                    if not health['healthy']:
                        azure_state = get_container_app_state(container_client, rg_name, app_name)
                        failed_apps.append({
                            'subscription': sub_name,
                            'resource_group': rg_name,
                            'app_name': app_name,
                            'url': url,
                            'status_code': health['status_code'],
                            'response_time': health['response_time'],
                            'error': health['error'],
                            'azure_state': azure_state
                        })
                        logger.warning(f"App unhealthy: {app_name} - {health['error']} | State: {azure_state}")

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
                        'azure_state': 'ERROR'
                    })

    if failed_apps:
        plain_report = "Azure Container App Health Alert\n\n"
        plain_report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        for item in failed_apps:
            status = f"HTTP {item['status_code']}" if item['status_code'] else f"ERROR: {item['error']}"
            plain_report += (
                f"Subscription: {item['subscription']}\n"
                f"Resource Group: {item['resource_group']}\n"
                f"App Name: {item['app_name']}\n"
                f"URL: {item['url']}\n"
                f"Azure State: {item['azure_state']}\n"
                f"Status: {status}\n"
                f"Response Time: {item.get('response_time', 'N/A')}s\n"
                f"Details: {item.get('error', 'N/A')}\n"
                f"{'-'*50}\n"
            )
        html_report = generate_html_report(failed_apps)
        send_summary_email(plain_report, html_report)
    else:
        logger.info("All container apps are healthy.")

if __name__ == "__main__":
    logger.info("Starting Azure Container App health check")
    check_all_container_apps()
    logger.info("Health check completed")
