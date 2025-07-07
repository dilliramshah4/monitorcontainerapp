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
    subject = "[Pangea] Unhealthy Azure Container Apps Detected"

    recipients = [email.strip() for email in TO_EMAIL.split(",")]

    msg = MIMEText(report_body)
    msg["Subject"] = subject
    msg["From"] = EMAIL
    msg["To"] = ", ".join(recipients)

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL, EMAIL_PASSWORD)
            server.sendmail(EMAIL, recipients, msg.as_string())
            print(f"📧 Email sent successfully to: {recipients}")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")

# === Check Container Apps Across All Subscriptions ===
def check_all_container_apps():
    full_report = "Dear Pangea Production Team,\n\nUnhealthy Azure Container Apps have been detected:\n"
    any_unhealthy = False  # Only trigger mail if True

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

                try:
                    apps = container_client.container_apps.list_by_resource_group(rg_name)
                    for app in apps:
                        app_name = app.name
                        try:
                            details = container_client.container_apps.get(rg_name, app_name)
                            status = details.provisioning_state

                            if status not in ["Succeeded", "Running"]:
                                any_unhealthy = True
                                full_report += f"\n📦 Subscription: {sub_name}\n📁 Resource Group: {rg_name}\n⚠️ Unhealthy App:\n  - {app_name}: {status}\n"

                        except HttpResponseError as e:
                            any_unhealthy = True
                            full_report += f"\n📦 Subscription: {sub_name}\n📁 Resource Group: {rg_name}\n❌ Failed to fetch app: {app_name}, Error: {e.message}\n"

                except Exception as e:
                    print(f"❌ Error listing apps in RG '{rg_name}': {e}")
                    continue

        except Exception as e:
            print(f"❌ Failed for subscription {sub_name}: {e}")
            continue

    if any_unhealthy:
        full_report += "\nPlease take action if necessary.\n\nThis is an automated message.\n\nRegards,\nProduction Team\nPangea Platform"
        send_summary_email(full_report)
    else:
        print("✅ All container apps are healthy. No email sent.")

# === Main Entry ===
if __name__ == "__main__":
    check_all_container_apps()
