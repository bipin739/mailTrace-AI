"""
Curated representative training dataset for NLP-based phishing classification.
Contains balanced samples across legitimate enterprise/personal communications
and realistic modern phishing attacks (credential theft, BEC, suspension, wire scams, lures).
"""
from typing import List, Tuple, Dict


DATASET: List[Dict[str, str]] = [
    # -------------------------------------------------------------
    # PHISHING SAMPLES (label = "phishing", target = 1)
    # -------------------------------------------------------------
    {
        "subject": "Urgent: Microsoft 365 Password Expiration Notice",
        "body": "Your Microsoft Office 365 password expires today. If you do not update your password immediately, your mailbox and OneDrive access will be suspended. Please verify your credentials at http://login-microsoft-secure.com/verify to retain active account status.",
        "label": "phishing"
    },
    {
        "subject": "Security Alert: Unusual Sign-in Attempt Detected",
        "body": "We detected an unauthorized login attempt to your Google Workspace account from IP 185.220.101.5 in Moscow, Russia. If this was not you, confirm your identity and reset your security credentials immediately at http://accounts-google-verify.ru/checkpoint.",
        "label": "phishing"
    },
    {
        "subject": "Action Required: Your PayPal Account Has Been Suspended",
        "body": "Dear customer, We noticed suspicious activity on your PayPal account. As a security measure, we have temporarily restricted account access and card payments. To restore full functionality, please verify your account and credit card details at http://paypal-resolution-center.net/login.",
        "label": "phishing"
    },
    {
        "subject": "URGENT WIRE TRANSFER REQUEST - Acquisition Milestone",
        "body": "Are you at your desk? We need to execute an urgent wire payment of $48,500 for the acquisition vendor closing today. The wire details are attached. Please process this payment immediately and confirm once the remittance advice is generated. Do not mention this to anyone as the deal is under NDA.",
        "label": "phishing"
    },
    {
        "subject": "DHL Express: Package #948201 Shipment Exception",
        "body": "DHL parcel #948201 could not be delivered to your registered delivery address due to unpaid customs duties of $3.50. You must pay the fee and confirm your delivery address at http://dhl-delivery-tracking.info/pay within 24 hours or the parcel will be returned to sender.",
        "label": "phishing"
    },
    {
        "subject": "Bank of America: Mandatory Security Update Required",
        "body": "Valued customer, Your online banking profile requires mandatory security re-validation under federal regulation. Failure to update your security questions and routing details will result in temporary suspension of electronic fund transfers. Log in now at http://bankofamerica-secure-auth.top.",
        "label": "phishing"
    },
    {
        "subject": "Payroll Update: Please Verify Your Direct Deposit Information",
        "body": "Due to our end-of-quarter payroll audit, all employees must review and re-confirm their direct deposit bank routing number and account number. Failure to do so will delay your upcoming payroll disbursement. Please access the employee self-service portal at http://workday-portal-update.org/login.",
        "label": "phishing"
    },
    {
        "subject": "Geek Squad: Auto-Renewal Invoice #GS-89104",
        "body": "Thank you for your business. Your annual subscription for Geek Squad Total Tech Protection has automatically renewed for $499.99. The amount was debited from your checking account. If you did not authorize this charge or wish to dispute it, call our toll-free fraud helpline immediately at 1-800-555-0199.",
        "label": "phishing"
    },
    {
        "subject": "DocuSign: Please sign Purchase Agreement 2026.pdf",
        "body": "You have received a new document for signature from Legal Department via DocuSign. Document: Vendor_Master_Agreement_Signed.pdf. Please review and sign the document by visiting http://docusign-envelope-review.com/auth before 5:00 PM EST today.",
        "label": "phishing"
    },
    {
        "subject": "Quick favor - are you available?",
        "body": "I'm tied up in board meetings all day with limited mobile service. Could you do me a quick favor? I need to purchase 10 Apple gift cards ($100 each) for client appreciation rewards. Please purchase them, scratch the back codes, and email the photos to me directly. I will reimburse you on company expense tomorrow.",
        "label": "phishing"
    },
    {
        "subject": "IRS Notification: Unclaimed Tax Refund Available",
        "body": "Internal Revenue Service Notice: Our records indicate you have an eligible unclaimed tax refund of $1,420.50 from your 2025 tax filing. To claim your tax refund directly into your bank account, submit your direct deposit details and Social Security Number at http://irs-tax-refund-claim.gov.us-portal.cc.",
        "label": "phishing"
    },
    {
        "subject": "Account De-activation Warning - IT Help Desk",
        "body": "All corporate staff: We are migrating email services to a new secure server. Any user mailbox that does not complete synchronization within 48 hours will be permanently deleted from the active directory. Confirm your username and password at http://ithelpdesk-auth-sync.net/owa.",
        "label": "phishing"
    },
    {
        "subject": "Netflix: Your membership payment could not be processed",
        "body": "We were unable to process your payment for the next billing cycle of Netflix. Your streaming access is on hold. Please update your billing information and payment card at http://netflix-account-restart.com/billing to resume watching.",
        "label": "phishing"
    },
    {
        "subject": "Wells Fargo: Fraudulent Debit Card Transaction Blocked",
        "body": "Wells Fargo Fraud Prevention: We detected an online transaction of $842.00 at BestBuy.com using your debit card. If you did not make this purchase, click http://wellsfargo-card-protection.com/dispute to cancel the payment and freeze your card.",
        "label": "phishing"
    },
    {
        "subject": "Invoice Overdue - Immediate Payment Required - Account 4920",
        "body": "Attention Accounts Payable: Attached is overdue invoice #INV-4920 for professional consulting services in the amount of $14,350. Please note that our banking details have recently changed. Remit wire payment to our new JPMorgan Chase account immediately to avoid collections.",
        "label": "phishing"
    },
    {
        "subject": "HR Notice: Revised 2026 Remote Work Policy and Benefits",
        "body": "Management has published the revised remote work policy and employee healthcare compensation adjustments for 2026. All employees are required to read the attached document and acknowledge receipt via the external portal: http://hr-benefits-ack.site/view.",
        "label": "phishing"
    },
    {
        "subject": "Amazon Security: Your account is locked due to suspicious orders",
        "body": "Your Amazon account has been locked after an unauthorized purchase of iPhone 16 Pro Max shipped to Miami, FL. If you did not authorize this purchase, verify your identity and credit card details at http://amazon-security-center.co/unlock.",
        "label": "phishing"
    },
    {
        "subject": "Meta / Instagram: Copyright Infringement Notice",
        "body": "Your Instagram account @handle has violated our Community Guidelines regarding intellectual property and copyright. If you believe this complaint is an error, submit an appeal within 24 hours at http://instagram-copyright-appeals.com/form or your account will be permanently disabled.",
        "label": "phishing"
    },
    {
        "subject": "Dropbox: Shared Financial Statement Q2.zip",
        "body": "Chief Financial Officer shared confidential file 'Audit_Financial_Report_Q2_2026.zip' with you on Dropbox. Click here to view file: http://dropbox-secure-file-share.org/download. Sign in with your corporate email password to download.",
        "label": "phishing"
    },
    {
        "subject": "Adobe Creative Cloud: Payment past due",
        "body": "Your Adobe Creative Cloud subscription is past due. To prevent interruption of your Illustrator, Photoshop, and Acrobat services, please update your credit card information at http://adobe-subscription-billing.net/card.",
        "label": "phishing"
    },
    {
        "subject": "USPS: We tried to deliver your parcel",
        "body": "United States Postal Service was unable to deliver item #US938104820 because nobody was present to sign. Reschedule your delivery online and pay the $1.99 redelivery fee at http://usps-redelivery-tracking.info/schedule.",
        "label": "phishing"
    },
    {
        "subject": "LinkedIn: You have 3 urgent unread messages",
        "body": "Recruiter from Global Cyber Defense sent you an executive opportunity message. Click here to read your message and update your credentials: http://linkedin-career-portal.info/messages.",
        "label": "phishing"
    },
    {
        "subject": "Apple ID: Your subscription has been renewed",
        "body": "You purchased 1-year subscription to VIP Dating Pro ($89.99/year) on your Apple ID. If you did not make this purchase, cancel and refund immediately at http://appleid-cancel-subscription.net/verify.",
        "label": "phishing"
    },
    {
        "subject": "Voicemail Notification: You received a 42-second voice message",
        "body": "PBX Telephony System: You received a new audio message from caller +1 (415) 890-1294. Click here to listen to your voice message: http://office-voicemail-telephony.top/play?id=9382.",
        "label": "phishing"
    },
    {
        "subject": "Urgent: Direct wire transfer verification needed",
        "body": "Please wire $75,000 to the overseas supplier specified in the invoice. The goods cannot be released from customs without immediate payment. Routing code and SWIFT number are confirmed. Process before wire cutoff at 3 PM.",
        "label": "phishing"
    },

    # -------------------------------------------------------------
    # LEGITIMATE SAMPLES (label = "legitimate", target = 0)
    # -------------------------------------------------------------
    {
        "subject": "Weekly Engineering Sync - Notes and Action Items",
        "body": "Hi team, Thanks for joining today's sprint sync. Here is the summary of what we discussed: 1. Frontend redesign is 80% complete, on track for Thursday QA. 2. Backend database migration scheduled for Saturday maintenance window. 3. Please review PR #142 when you have a moment. Let me know if anyone has blockers.",
        "label": "legitimate"
    },
    {
        "subject": "Project Status Update: Sprint 42 Milestones",
        "body": "Hello everyone, We have completed 38 out of 42 story points in the current sprint. Outstanding items include the unit test coverage for the DNS parser and documentation updates for Section 10. We will carry over the remaining two tasks to Sprint 43. Have a great evening!",
        "label": "legitimate"
    },
    {
        "subject": "Lunch and Learn: Introduction to Graph Databases next Tuesday",
        "body": "Hi all, Please join us next Tuesday at 12:30 PM in Conference Room B for our monthly tech talk. Alex will be presenting an introduction to Neo4j and knowledge graphs. Pizza and refreshments will be provided by the company. RSVP on the calendar invite so we know how much food to order.",
        "label": "legitimate"
    },
    {
        "subject": "Your Amazon.com order #114-8921849-019283 has shipped",
        "body": "Hello Sam, We wanted to let you know that your order containing 'Designing Data-Intensive Applications' has shipped via UPS. You can track your package on Amazon.com or UPS.com. Estimated delivery is Friday by 8:00 PM. Thank you for shopping with us.",
        "label": "legitimate"
    },
    {
        "subject": "Scheduled Network Maintenance: Sunday 2:00 AM - 4:00 AM UTC",
        "body": "The infrastructure team will be performing core switch firmware upgrades this Sunday morning between 02:00 and 04:00 UTC. During this window, brief intermittent connectivity drops of up to 5 minutes may occur. Internal staging environments will be rebooted. Production services with multi-region redundancy will remain available.",
        "label": "legitimate"
    },
    {
        "subject": "Receipt for your GitHub Copilot for Business Subscription",
        "body": "Thank you for your payment of $19.00 USD. Your invoice #GH-2026-0391 has been paid via credit card ending in 4019. You can download your official tax receipt from your GitHub Organization Billing settings anytime. No further action is required.",
        "label": "legitimate"
    },
    {
        "subject": "Welcome Sarah to the Security Operations Team!",
        "body": "Team, please join me in welcoming Sarah Johnson, who joins our team today as a Senior SOC Analyst. Sarah brings over 7 years of threat hunting and incident response experience from Mandiant. She will be sitting in Pod C on the 3rd floor. Feel free to stop by and say hello!",
        "label": "legitimate"
    },
    {
        "subject": "Notes from today's Product Design Review",
        "body": "Attached are the design specs and wireframes discussed in our review today. Key takeaways: We agreed on the simplified two-column navigation layout and dark cybersecurity theme. Contrast ratios pass WCAG AA standards. Next milestone is the interactive prototype review on Friday.",
        "label": "legitimate"
    },
    {
        "subject": "Flight Confirmation - United Airlines UA 482 SFO to ORD",
        "body": "Confirmation code: HK982X. Passenger: Sam Mishra. Flight UA 482 departs San Francisco (SFO) at 08:30 AM on October 14, arriving in Chicago O'Hare (ORD) at 02:45 PM. Seat assignment: 12B (Economy Plus). Check-in opens 24 hours prior to departure on the United app.",
        "label": "legitimate"
    },
    {
        "subject": "Python Weekly Newsletter - Issue 620",
        "body": "Welcome to issue 620 of Python Weekly. This week's featured articles: 1. Python 3.14 performance benchmarks and new typing features. 2. Building scalable background workers with AnyIO. 3. Fast and interpretable NLP text classification using scikit-learn. Check out the community projects section on GitHub.",
        "label": "legitimate"
    },
    {
        "subject": "Company All-Hands Meeting Agenda - Q3 Kickoff",
        "body": "Hi team, Reminder that our quarterly All-Hands will take place this Thursday at 10:00 AM PT in the main auditorium and via Zoom. We will review our Q2 revenue results, showcase the new enterprise product release, and host an open Q&A session with the leadership team.",
        "label": "legitimate"
    },
    {
        "subject": "Code Review Request: Refactor authentication header parser #189",
        "body": "Hey team, I submitted PR #189 for review. It refactors the SPF, DKIM, and DMARC header extraction logic into separate modular parsing methods and adds test coverage for edge cases like duplicate Authentication-Results headers. Please take a look when you have bandwidth.",
        "label": "legitimate"
    },
    {
        "subject": "Your Uber trip on Monday morning",
        "body": "Thanks for riding with Uber, Sam. Total: $24.85. Fare breakdown: Base fare $3.50, Distance $14.20, Time $4.15, City surcharge $3.00. Payment method: Apple Pay (Visa ending in 8192). We hope you enjoyed your ride with driver Carlos.",
        "label": "legitimate"
    },
    {
        "subject": "Office Holiday Schedule: Memorial Day Closure",
        "body": "All staff: Please be reminded that corporate offices will be closed on Monday, May 25th in observance of Memorial Day. Emergency support and on-call rotations will continue as scheduled. Normal business operations will resume on Tuesday morning. Enjoy the long weekend!",
        "label": "legitimate"
    },
    {
        "subject": "Dental appointment reminder for Tuesday at 3:00 PM",
        "body": "Hi Sam, This is a friendly reminder of your upcoming routine dental cleaning appointment with Dr. Miller on Tuesday, October 20th at 3:00 PM. Please arrive 10 minutes early. If you need to reschedule, please call our office at least 24 hours in advance.",
        "label": "legitimate"
    },
    {
        "subject": "Slack: You were mentioned in #secops-alerts",
        "body": "@sam: Can you take a look at the firewall logs for the DNS resolver node when you get a chance? No rush, just wanted your second opinion before we rotate the keys. Thanks!",
        "label": "legitimate"
    },
    {
        "subject": "Conference Registration Confirmation - DEF CON 34",
        "body": "Thank you for registering for DEF CON 34. Your registration ID is DC34-889104. Pick up your physical conference badge at the Caesars Forum registration desk starting Thursday at 8:00 AM. Bring your confirmation QR code and government-issued photo ID.",
        "label": "legitimate"
    },
    {
        "subject": "Draft Proposal: Threat Intelligence Sharing Pipeline",
        "body": "Hi Dave, I drafted the proposal document for automating our IOC ingestion pipeline from MISP and AlienVault OTX. I shared the Google Doc with you for commenting. Looking forward to discussing this in our 1-on-1 meeting tomorrow.",
        "label": "legitimate"
    },
    {
        "subject": "Your monthly utility electric bill is ready to view",
        "body": "Your Pacific Gas & Electric billing statement for September is now available online. Total amount due: $118.42. Due date: October 22. Autopay is scheduled to process on October 18 from your checking account ending in 5102.",
        "label": "legitimate"
    },
    {
        "subject": "Release Notes: v2.4.0 of Forensic Email Parser Engine",
        "body": "Team, v2.4.0 has been deployed to production. Changes in this release include: 1. Improved relay hop timestamp parsing across diverse MTA formats. 2. Lookalike domain detection Levenshtein threshold tuning. 3. Zero regressions in the test suite.",
        "label": "legitimate"
    },
    {
        "subject": "Coffee catch-up next week?",
        "body": "Hey Sam, Hope you're doing well! It's been a while since we caught up. Are you free for coffee sometime next Wednesday or Thursday afternoon around 2 PM? Let me know what your schedule looks like.",
        "label": "legitimate"
    },
    {
        "subject": "GitLab: Pipeline #84910 passed on branch feature/ioc-extractor",
        "body": "Pipeline #84910 passed for commit 9b8a32f on branch feature/ioc-extractor. All 69 unit tests passed successfully in 18 seconds. Coverage report is available in the job artifacts.",
        "label": "legitimate"
    },
    {
        "subject": "Quarterly Ergonomic Assessment Sign-ups Available",
        "body": "Workplace Facilities Team: Our quarterly ergonomic evaluations will take place next Wednesday. If you would like a certified specialist to assess your desk setup and monitor height, please sign up for a 15-minute slot on the intranet portal.",
        "label": "legitimate"
    },
    {
        "subject": "Package delivered: Front Door",
        "body": "Your package from REI was delivered at 1:45 PM on Thursday and placed near the front door. Package tracking number: 1Z9840291048201. If you have not received this shipment, please contact customer support.",
        "label": "legitimate"
    },
    {
        "subject": "Research Paper: Detection of Advanced Email Spoofing Techniques",
        "body": "Hi team, Sharing an interesting paper published at IEEE S&P regarding sender policy framework bypasses in multi-tenant cloud environments. It provides good context for our upcoming DMARC alignment enhancements. Happy reading!",
        "label": "legitimate"
    }
]


def get_training_corpus() -> Tuple[List[str], List[int]]:
    """
    Returns (texts, labels) where:
    - texts are combined 'Subject: <subject>\n\n<body>'
    - labels are 1 for phishing and 0 for legitimate
    """
    texts = []
    labels = []
    for item in DATASET:
        subject = item.get("subject", "")
        body = item.get("body", "")
        combined = f"Subject: {subject}\n\n{body}"
        texts.append(combined)
        labels.append(1 if item["label"] == "phishing" else 0)
    return texts, labels
