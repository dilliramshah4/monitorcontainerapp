#!/usr/bin/env python3

import os
import smtplib
from email.mime.text import MIMEText
from azure.identity import ClientSecretCredential
from azure.mgmt.resource import SubscriptionClient, ResourceManagementClient
from azure.mgmt.appcontainers import ContainerAppsAPIClient
from azure.core.exceptions import HttpResponseError

# === Environment Variables from GitHub Actions Secrets ===
EMAIL = os.getenv("EMAIL")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
TO_EMAIL = os.getenv("TO_EMAIL")
AZURE_CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
AZURE_CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")
AZURE_TENANT_ID = os.getenv("AZURE_TENANT_ID")

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

# === Authenticate with Azure using Service Principal ===
credential = ClientSecretCredential(
    tenant_id=AZURE_TENANT_ID,
    client_id=AZURE_CLIENT_ID,
    client_secret=AZURE_CLIENT_SECRET
)
sub_client = SubscriptionClient(credential)

# === Send Email ===
def send_summary_email(report_body: str):
    subject = "[Pangea] Azure Container Apps Health Report"

    msg = MIMEText(report_body)
    msg["Subject"] = subject
    msg["From"] = EMAIL
    msg["To"] = TO_EMAIL

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL, EMAIL_PASSWORD)
            server.sendmail(EMAIL, TO_EMAIL, msg.as_string())
            print("📧 Email sent successfully")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")

# === Check Container Apps Across All Subscriptions ===
def check_all_container_apps():
    full_report = "Dear Pangea Production Team,\n\nHere is the latest health status of Azure Container Apps:\n"

    for sub in sub_client.subscriptions.list():
        sub_id = sub.subscription_id
        sub_name = sub.display_name
        print(f"\n📦 Subscription: {sub_name} ({sub_id})")

        try:
            rg_client = ResourceManagementClient(credential, sub_id)
            container_client = ContainerAppsAPIClient(credential, sub_id)

            for rg in rg_client.resource_groups.list():
                rg_name = rg.name
                print(f"\n🔍 Resource Group: {rg_name}")

                healthy_apps = {}
                unhealthy_apps = {}

                try:
                    apps = container_client.container_apps.list_by_resource_group(rg_name)
                    for app in apps:
                        app_name = app.name
                        try:
                            details = container_client.container_apps.get(rg_name, app_name)
                            status = details.provisioning_state
                            if status in ["Succeeded", "Running"]:
                                healthy_apps[app_name] = status
                            else:
                                unhealthy_apps[app_name] = status
                        except HttpResponseError as e:
                            unhealthy_apps[app_name] = f"Error: {e.message}"
                except Exception as e:
                    print(f"❌ Error listing apps in RG '{rg_name}': {e}")
                    continue

                # Format the section for this RG
                full_report += f"\n📦 Subscription: {sub_name}\n📁 Resource Group: {rg_name}\n"
                if healthy_apps:
                    full_report += "✅ Healthy Apps:\n"
                    for name, stat in healthy_apps.items():
                        full_report += f"  - {name}: {stat}\n"
                else:
                    full_report += "✅ No healthy apps found.\n"

                if unhealthy_apps:
                    full_report += "\n⚠️ Unhealthy Apps:\n"
                    for name, stat in unhealthy_apps.items():
                        full_report += f"  - {name}: {stat}\n"
                else:
                    full_report += "\n🎉 No unhealthy apps detected.\n"

        except Exception as e:
            print(f"❌ Failed for subscription {sub_name}: {e}")
            continue

    full_report += "\n\nThis is an automated email.\n\nRegards,\nMonitoring System\nPangea Platform"
    send_summary_email(full_report)

# === Main Entry ===
if __name__ == "__main__":
    check_all_container_apps()
