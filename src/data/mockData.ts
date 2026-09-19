import type { EmailAnalysisData, InvestigationCase, ThreatIntelligenceCluster, ForensicReport, SystemSettings } from '../types';

export const INITIAL_SETTINGS: SystemSettings = {
  anonymizeTargetPII: true,
  maskEmailAddresses: false,
  retentionPeriodDays: 90,
  autoEscalateThreshold: 85,
  sha256ChainOfCustody: true,
  enableRealTimeAlerts: true,
  webhookUrl: 'https://soc.enterprise-sec.internal/hooks/mailtrace-alerts',
  allowedIpSubnets: '10.0.0.0/8, 172.16.0.0/12'
};

export const SAMPLE_EMAILS: EmailAnalysisData[] = [
  {
    id: 'EML-2026-8819',
    subject: 'URGENT: Executive Wire Transfer Instructions - Q3 Vendor Settlement #8819',
    senderName: 'Robert Vance (CEO)',
    senderEmail: 'robert.vance@bank-corp-update.com',
    returnPath: 'bounce-gateway@wire-transfer-node.ru',
    replyTo: 'financial-operations-secure@wire-transfer-node.ru',
    recipientEmail: 'sarah.jenkins@finance.bankcorp.com',
    timestamp: '2026-09-05 10:42:15 UTC',
    riskScore: 96,
    severity: 'CRITICAL',
    category: 'BEC Fraud',
    summary: 'High-confidence Business Email Compromise (BEC) payment diversion attempt using a deceptive domain lookalike (bank-corp-update.com vs bankcorp.com), Return-Path spoofing, and urgent CFO wire transfer request language.',
    nlpFlags: {
      urgencyCues: true,
      financialDiversionLanguage: true,
      credentialHarvestingKeywords: false,
      authorityImpersonation: true,
      nlpScore: 94
    },
    protocols: {
      spf: 'FAIL',
      spfDetails: 'SoftFail domain bank-corp-update.com does not designate 185.220.101.42 as permitted sender',
      dkim: 'FAIL',
      dkimDetails: 'Signature verification failed; header hash mismatch on selector default._domainkey',
      dmarc: 'FAIL',
      dmarcDetails: 'p=reject policy triggered due to SPF/DKIM alignment failure',
      returnPathMatch: false,
      replyToMismatch: true
    },
    originGeo: {
      ip: '185.220.101.42',
      country: 'Russia',
      countryCode: 'RU',
      city: 'Moscow',
      region: 'Moscow Oblast',
      latitude: 55.7558,
      longitude: 37.6173,
      isp: 'St. Petersburg Digital Hosting Co.',
      asn: 'AS49281',
      isVpn: true,
      isTor: true,
      isProxy: true,
      isDatacenter: true
    },
    hops: [
      {
        hopNumber: 1,
        fromHost: 'smtp-relay-01.shadow-node.ru',
        fromIp: '185.220.101.42',
        byHost: 'edge-gateway-eu.mail-forwarder.net',
        byIp: '194.165.16.88',
        timestamp: '10:41:02 UTC',
        delaySeconds: 2,
        country: 'Russia',
        city: 'Moscow',
        org: 'ShadowNode Hosting',
        isOrigin: true,
        isSuspicious: true,
        notes: 'Earliest reliable sending server (Originating Node). TOR exit node flag active.'
      },
      {
        hopNumber: 2,
        fromHost: 'edge-gateway-eu.mail-forwarder.net',
        fromIp: '194.165.16.88',
        byHost: 'mx01.bankcorp.com',
        byIp: '20.190.144.12',
        timestamp: '10:41:45 UTC',
        delaySeconds: 43,
        country: 'Netherlands',
        city: 'Amsterdam',
        org: 'Cloud Transit Subnet',
        isOrigin: false,
        isSuspicious: false,
        notes: 'Intermediate anonymizing proxy relay.'
      },
      {
        hopNumber: 3,
        fromHost: 'mx01.bankcorp.com',
        fromIp: '20.190.144.12',
        byHost: 'mail-inbound-protect.bankcorp.internal',
        byIp: '10.200.4.15',
        timestamp: '10:42:15 UTC',
        delaySeconds: 30,
        country: 'United States',
        city: 'New York',
        org: 'BankCorp Enterprise Gateway',
        isOrigin: false,
        isSuspicious: false,
        notes: 'Internal security gateway boundary.'
      }
    ],
    iocs: {
      ips: ['185.220.101.42', '194.165.16.88'],
      domains: ['bank-corp-update.com', 'wire-transfer-node.ru'],
      urls: [
        {
          url: 'http://wire-transfer-node.ru/verify-invoice-auth?ref=8819',
          domain: 'wire-transfer-node.ru',
          isObfuscated: true,
          riskScore: 98
        }
      ],
      hashes: [
        {
          filename: 'Vendor_Invoice_Q3_Settlement.pdf.exe',
          md5: 'e99a18c428cb38d5f260853678922e03',
          sha256: 'a68194f56f481c1c1f7a08b52f9547d25e0c65192bd88741029c72e29381664c',
          isMalicious: true
        }
      ],
      emails: ['financial-operations-secure@wire-transfer-node.ru', 'bounce-gateway@wire-transfer-node.ru']
    },
    rawHeaders: `Received: from mx01.bankcorp.com (20.190.144.12) by mail-inbound-protect.bankcorp.internal (10.200.4.15) with SMTP id s8819; Sat, 5 Sep 2026 10:42:15 UTC
Received: from edge-gateway-eu.mail-forwarder.net (194.165.16.88) by mx01.bankcorp.com with ESMTPS id p4102 for <sarah.jenkins@bankcorp.com>; Sat, 5 Sep 2026 10:41:45 UTC
Received: from smtp-relay-01.shadow-node.ru (185.220.101.42) by edge-gateway-eu.mail-forwarder.net with ESMTP id r9182; Sat, 5 Sep 2026 10:41:02 UTC
Return-Path: <bounce-gateway@wire-transfer-node.ru>
Reply-To: financial-operations-secure@wire-transfer-node.ru
From: "Robert Vance (CEO)" <robert.vance@bank-corp-update.com>
To: sarah.jenkins@finance.bankcorp.com
Subject: URGENT: Executive Wire Transfer Instructions - Q3 Vendor Settlement #8819
Date: Sat, 5 Sep 2026 10:41:00 UTC
Message-ID: <20260905.8819-shadow@bank-corp-update.com>
Authentication-Results: mx01.bankcorp.com;
  spf=fail (sender IP 185.220.101.42) smtp.mailfrom=bounce-gateway@wire-transfer-node.ru;
  dkim=fail (signature mismatch) header.i=@bank-corp-update.com;
  dmarc=fail (p=reject dis=reject) header.from=bank-corp-update.com
X-Mailer: Custom-SMTP-Engine-v4`,
    bodyText: `Sarah,

I am currently in an emergency board meeting with our acquisition partners. We need to process an immediate wire transfer of $248,500 USD for the Q3 vendor settlement before 12:00 PM EST today.

Due to an ongoing banking audit, do not use our standard internal portal. Please click the link below to download the updated wiring instructions and process the payment right away:

http://wire-transfer-node.ru/verify-invoice-auth?ref=8819

Please confirm once the transfer receipt is generated. Treat this request with utmost confidentiality.

Regards,
Robert Vance
Chief Executive Officer | BankCorp Global`,
    campaignId: 'CAMP-2026-FIN-RU',
    campaignName: 'Operation GhostInvoice'
  },
  {
    id: 'EML-2026-4402',
    subject: 'Action Required: Microsoft 365 Password Expiration & MFA Re-authentication',
    senderName: 'IT Support Security Admin',
    senderEmail: 'no-reply@m365-security-portal-verify.net',
    returnPath: 'alert@m365-security-portal-verify.net',
    replyTo: 'support@m365-security-portal-verify.net',
    recipientEmail: 'david.miller@bankcorp.com',
    timestamp: '2026-09-05 08:15:30 UTC',
    riskScore: 89,
    severity: 'HIGH',
    category: 'Credential Harvesting',
    summary: 'Deceptive Microsoft 365 brand impersonation email designed to harvest enterprise single sign-on (SSO) credentials. Features typosquatted domain m365-security-portal-verify.net hosted on bulletproof server in Romania.',
    nlpFlags: {
      urgencyCues: true,
      financialDiversionLanguage: false,
      credentialHarvestingKeywords: true,
      authorityImpersonation: true,
      nlpScore: 88
    },
    protocols: {
      spf: 'PASS',
      spfDetails: 'Sender domain m365-security-portal-verify.net designates IP 91.240.118.15 as valid sender',
      dkim: 'PASS',
      dkimDetails: 'Signature valid for m365-security-portal-verify.net, but domain is non-aligned with Microsoft',
      dmarc: 'FAIL',
      dmarcDetails: 'Organizational domain mismatch between display identity (Microsoft 365) and mailfrom header',
      returnPathMatch: true,
      replyToMismatch: false
    },
    originGeo: {
      ip: '91.240.118.15',
      country: 'Romania',
      countryCode: 'RO',
      city: 'Bucharest',
      region: 'Bucharest',
      latitude: 44.4323,
      longitude: 26.1063,
      isp: 'Voxility Bulletproof Hosting',
      asn: 'AS39743',
      isVpn: false,
      isTor: false,
      isProxy: true,
      isDatacenter: true
    },
    hops: [
      {
        hopNumber: 1,
        fromHost: 'srv-m365phish.voxility.net',
        fromIp: '91.240.118.15',
        byHost: 'relay.outbound-dns.com',
        byIp: '185.100.85.10',
        timestamp: '08:14:10 UTC',
        delaySeconds: 5,
        country: 'Romania',
        city: 'Bucharest',
        org: 'Voxility ASN',
        isOrigin: true,
        isSuspicious: true,
        notes: 'Known bulletproof phishing server.'
      },
      {
        hopNumber: 2,
        fromHost: 'relay.outbound-dns.com',
        fromIp: '185.100.85.10',
        byHost: 'mx01.bankcorp.com',
        byIp: '20.190.144.12',
        timestamp: '08:15:30 UTC',
        delaySeconds: 80,
        country: 'United States',
        city: 'New York',
        org: 'BankCorp Enterprise Gateway',
        isOrigin: false,
        isSuspicious: false
      }
    ],
    iocs: {
      ips: ['91.240.118.15', '185.100.85.10'],
      domains: ['m365-security-portal-verify.net'],
      urls: [
        {
          url: 'https://m365-security-portal-verify.net/login/sso?user=david.miller@bankcorp.com',
          domain: 'm365-security-portal-verify.net',
          isObfuscated: false,
          riskScore: 92
        }
      ],
      hashes: [],
      emails: ['no-reply@m365-security-portal-verify.net']
    },
    rawHeaders: `Received: from mx01.bankcorp.com (20.190.144.12) by mail-inbound.bankcorp.internal (10.200.4.15) with ESMTP id m4402; Sat, 5 Sep 2026 08:15:30 UTC
Received: from relay.outbound-dns.com (185.100.85.10) by mx01.bankcorp.com; Sat, 5 Sep 2026 08:14:15 UTC
From: "IT Support Security Admin" <no-reply@m365-security-portal-verify.net>
To: david.miller@bankcorp.com
Subject: Action Required: Microsoft 365 Password Expiration & MFA Re-authentication
Date: Sat, 5 Sep 2026 08:14:10 UTC
Message-ID: <202609050814.m365phish@m365-security-portal-verify.net>`,
    bodyText: `Dear David,

Your Microsoft 365 password for account david.miller@bankcorp.com is scheduled to expire in 4 hours. 

To maintain continuous access to your emails, SharePoint documents, and Teams messages, you must re-verify your password and Multi-Factor Authentication (MFA) token immediately.

Click here to start re-authentication:
https://m365-security-portal-verify.net/login/sso?user=david.miller@bankcorp.com

If you do not update your credentials within 4 hours, your account will be locked by system policy.

Best Regards,
IT Global Helpdesk Security`,
    campaignId: 'CAMP-2026-M365-RO',
    campaignName: 'Lazarus M365 Harvester'
  },
  {
    id: 'EML-2026-3190',
    subject: 'Quarterly Financial Performance Briefing & Board Slides - Q2 2026',
    senderName: 'Elena Rostova (VP Finance)',
    senderEmail: 'elena.rostova@bankcorp.com',
    returnPath: 'elena.rostova@bankcorp.com',
    replyTo: 'elena.rostova@bankcorp.com',
    recipientEmail: 'exec-committee@bankcorp.com',
    timestamp: '2026-09-05 07:10:00 UTC',
    riskScore: 4,
    severity: 'LEGITIMATE',
    category: 'Legitimate',
    summary: 'Legitimate internal communication from verified VP of Finance. SPF, DKIM, and DMARC signatures fully aligned with bankcorp.com corporate Exchange infrastructure.',
    nlpFlags: {
      urgencyCues: false,
      financialDiversionLanguage: false,
      credentialHarvestingKeywords: false,
      authorityImpersonation: false,
      nlpScore: 2
    },
    protocols: {
      spf: 'PASS',
      spfDetails: 'IP 40.107.12.45 matches Microsoft 365 SPF record v=spf1 include:spf.protection.outlook.com -all',
      dkim: 'PASS',
      dkimDetails: 'DKIM signature s=selector1 d=bankcorp.com verified successfully',
      dmarc: 'PASS',
      dmarcDetails: 'DMARC alignment passed with p=reject policy',
      returnPathMatch: true,
      replyToMismatch: false
    },
    originGeo: {
      ip: '40.107.12.45',
      country: 'United States',
      countryCode: 'US',
      city: 'Redmond',
      region: 'Washington',
      latitude: 47.674,
      longitude: -122.1215,
      isp: 'Microsoft Corporation',
      asn: 'AS8075',
      isVpn: false,
      isTor: false,
      isProxy: false,
      isDatacenter: true
    },
    hops: [
      {
        hopNumber: 1,
        fromHost: 'mail-redmond01.outbound.protection.outlook.com',
        fromIp: '40.107.12.45',
        byHost: 'mx01.bankcorp.com',
        byIp: '20.190.144.12',
        timestamp: '07:09:50 UTC',
        delaySeconds: 10,
        country: 'United States',
        city: 'Redmond',
        org: 'Microsoft Exchange Online',
        isOrigin: true,
        isSuspicious: false
      }
    ],
    iocs: {
      ips: ['40.107.12.45'],
      domains: ['bankcorp.com'],
      urls: [],
      hashes: [],
      emails: ['elena.rostova@bankcorp.com']
    },
    rawHeaders: `Received: from mail-redmond01.outbound.protection.outlook.com (40.107.12.45) by mx01.bankcorp.com; Sat, 5 Sep 2026 07:10:00 UTC
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=bankcorp.com; s=selector1;
From: "Elena Rostova (VP Finance)" <elena.rostova@bankcorp.com>
To: exec-committee@bankcorp.com
Subject: Quarterly Financial Performance Briefing & Board Slides - Q2 2026`,
    bodyText: `Dear Executive Committee,

Attached are the finalized financial performance slides and risk evaluation audit for Q2 2026.

Key highlights:
- Revenue growth up 14.2% YoY
- Cyber risk compliance index maintained at 99.4%
- Zero fraud losses recorded in commercial accounts during the last quarter

Let me know if you have any questions ahead of Monday's board session.

Best regards,
Elena Rostova`,
    campaignId: undefined,
    campaignName: undefined
  },
  {
    id: 'EML-2026-9011',
    subject: 'Notice: Payroll Direct Deposit Update Request - Urgent Confirmation Needed',
    senderName: 'HR Department',
    senderEmail: 'payroll-servicedesk@bankcorp-hr-portal.com',
    returnPath: 'bounce@bankcorp-hr-portal.com',
    replyTo: 'hr-payroll-update@anonymized-relay.com',
    recipientEmail: 'mark.steven@bankcorp.com',
    timestamp: '2026-09-04 22:30:11 UTC',
    riskScore: 92,
    severity: 'HIGH',
    category: 'BEC Fraud',
    summary: 'Executive & HR impersonation attempt aimed at altering direct deposit banking routing information. Uses lookalike domain bankcorp-hr-portal.com with mismatching Reply-To address routed through open relay in Brazil.',
    nlpFlags: {
      urgencyCues: true,
      financialDiversionLanguage: true,
      credentialHarvestingKeywords: true,
      authorityImpersonation: true,
      nlpScore: 91
    },
    protocols: {
      spf: 'NEUTRAL',
      spfDetails: 'No valid SPF record configured for domain bankcorp-hr-portal.com',
      dkim: 'NONE',
      dkimDetails: 'No DKIM signature found in message header',
      dmarc: 'FAIL',
      dmarcDetails: 'Unauthenticated sending domain; failed policy evaluation',
      returnPathMatch: false,
      replyToMismatch: true
    },
    originGeo: {
      ip: '177.129.44.80',
      country: 'Brazil',
      countryCode: 'BR',
      city: 'São Paulo',
      region: 'São Paulo State',
      latitude: -23.5505,
      longitude: -46.6333,
      isp: 'Telemar Norte Leste S.A.',
      asn: 'AS7738',
      isVpn: false,
      isTor: false,
      isProxy: true,
      isDatacenter: false
    },
    hops: [
      {
        hopNumber: 1,
        fromHost: 'smtp-open.telemar.com.br',
        fromIp: '177.129.44.80',
        byHost: 'mx01.bankcorp.com',
        byIp: '20.190.144.12',
        timestamp: '22:29:05 UTC',
        delaySeconds: 66,
        country: 'Brazil',
        city: 'São Paulo',
        org: 'Telemar Broadband',
        isOrigin: true,
        isSuspicious: true,
        notes: 'Unauthenticated residential open relay node.'
      }
    ],
    iocs: {
      ips: ['177.129.44.80'],
      domains: ['bankcorp-hr-portal.com', 'anonymized-relay.com'],
      urls: [
        {
          url: 'http://bankcorp-hr-portal.com/update-payroll-direct-deposit',
          domain: 'bankcorp-hr-portal.com',
          isObfuscated: false,
          riskScore: 89
        }
      ],
      hashes: [],
      emails: ['hr-payroll-update@anonymized-relay.com']
    },
    rawHeaders: `Received: from smtp-open.telemar.com.br (177.129.44.80) by mx01.bankcorp.com; Fri, 4 Sep 2026 22:30:11 UTC
From: "HR Department" <payroll-servicedesk@bankcorp-hr-portal.com>
Reply-To: hr-payroll-update@anonymized-relay.com
To: mark.steven@bankcorp.com
Subject: Notice: Payroll Direct Deposit Update Request - Urgent Confirmation Needed`,
    bodyText: `Hi Mark,

We received a request to update your direct deposit bank account details for your upcoming salary disbursement on September 15.

If you initiated this change, please log in to verify your new account details:
http://bankcorp-hr-portal.com/update-payroll-direct-deposit

If you did not request this update, reply immediately to this email to freeze your payout.

HR Operations`,
    campaignId: 'CAMP-2026-PAYROLL-BR',
    campaignName: 'Operation DepositHijack'
  }
];

export const MOCK_CASES: InvestigationCase[] = [
  {
    id: 'CASE-2026-041',
    caseNumber: 'INV-2026-0905-01',
    title: 'High-Value Executive BEC & Wire Transfer Diversion Campaign',
    severity: 'CRITICAL',
    status: 'UNDER_INVESTIGATION',
    category: 'BEC Fraud',
    targetUser: 'sarah.jenkins@finance.bankcorp.com',
    targetDepartment: 'Finance & Treasury',
    senderEmail: 'robert.vance@bank-corp-update.com',
    originIp: '185.220.101.42',
    originCountry: 'Russia',
    fraudRiskScore: 96,
    assignedAnalyst: 'Alex Mercer (Lead Cyber Analyst)',
    createdAt: '2026-09-05 10:50:00 UTC',
    updatedAt: '2026-09-05 11:12:00 UTC',
    description: 'Active BEC campaign targeting financial controllers with spoofed CEO domain bank-corp-update.com. Originating IP traced to Russian TOR exit node linked with threat cluster Operation GhostInvoice.',
    relatedEmailIds: ['EML-2026-8819'],
    evidenceHashes: [
      'a68194f56f481c1c1f7a08b52f9547d25e0c65192bd88741029c72e29381664c',
      'e99a18c428cb38d5f260853678922e03'
    ],
    chainOfCustody: [
      {
        id: 'COC-101',
        timestamp: '2026-09-05 10:45:00 UTC',
        action: 'Automated Real-Time Ingestion',
        actor: 'MailTrace AI Ingestion Pipeline',
        details: 'Raw email EML-2026-8819 ingested and cryptographic hash SHA-256 computed: a68194f5...',
        hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
      },
      {
        id: 'COC-102',
        timestamp: '2026-09-05 10:50:00 UTC',
        action: 'Case Initialized & Risk Threshold Triggered',
        actor: 'SOC Auto-Dispatcher Rule #88',
        details: 'Fraud score 96% exceeded critical auto-escalation limit (85%). Case INV-2026-0905-01 generated.',
        hash: '685d38804e76a6616422b404d7d35368a523a9d949cf9d40b490a6e0cf8713cf'
      },
      {
        id: 'COC-103',
        timestamp: '2026-09-05 11:10:00 UTC',
        action: 'Firewall & Domain Quarantine Action',
        actor: 'Alex Mercer (Analyst ID: AM-902)',
        details: 'Submitted block rule for domain bank-corp-update.com and egress IP 185.220.101.42 to Perimeter Palo Alto Gateway.',
        hash: 'b10a8db164e0754105b7a99be72e3fe5daf6a07a2974c995f577cfc704f0556e'
      }
    ]
  },
  {
    id: 'CASE-2026-039',
    caseNumber: 'INV-2026-0905-02',
    title: 'Microsoft 365 Bulk SSO Credential Harvesting Attack',
    severity: 'HIGH',
    status: 'CONTAINED',
    category: 'Credential Harvesting',
    targetUser: 'david.miller@bankcorp.com',
    targetDepartment: 'IT Infrastructure',
    senderEmail: 'no-reply@m365-security-portal-verify.net',
    originIp: '91.240.118.15',
    originCountry: 'Romania',
    fraudRiskScore: 89,
    assignedAnalyst: 'Elena Vance (Security Specialist)',
    createdAt: '2026-09-05 08:30:00 UTC',
    updatedAt: '2026-09-05 09:15:00 UTC',
    description: 'Phishing campaign delivering lookalike Microsoft 365 authentication pages hosted on Voxility Bucharest IP. Targeted 45 employees across IT and Legal.',
    relatedEmailIds: ['EML-2026-4402'],
    evidenceHashes: [
      'f4a8b79c31e05d21a590b14c77112001'
    ],
    chainOfCustody: [
      {
        id: 'COC-201',
        timestamp: '2026-09-05 08:30:00 UTC',
        action: 'Ingestion & Forensic Parsing',
        actor: 'MailTrace AI Engine',
        details: 'Processed 45 matching emails across organization mailboxes.',
        hash: '772c918a221f001b66782d1c92589304'
      },
      {
        id: 'COC-202',
        timestamp: '2026-09-05 09:15:00 UTC',
        action: 'Domain Block & Token Revocation',
        actor: 'Elena Vance',
        details: 'Revoked M365 active sessions for 3 user accounts that clicked the link.',
        hash: '9910ba1e4d1f2a33c110291d295b9201'
      }
    ]
  },
  {
    id: 'CASE-2026-035',
    caseNumber: 'INV-2026-0904-04',
    title: 'Payroll Direct Deposit Routing Diversion Phishing',
    severity: 'HIGH',
    status: 'NEW',
    category: 'BEC Fraud',
    targetUser: 'mark.steven@bankcorp.com',
    targetDepartment: 'Human Resources',
    senderEmail: 'payroll-servicedesk@bankcorp-hr-portal.com',
    originIp: '177.129.44.80',
    originCountry: 'Brazil',
    fraudRiskScore: 92,
    assignedAnalyst: 'Unassigned',
    createdAt: '2026-09-04 22:45:00 UTC',
    updatedAt: '2026-09-04 22:45:00 UTC',
    description: 'Fake HR payroll direct deposit change email originating from open relay IP in Brazil.',
    relatedEmailIds: ['EML-2026-9011'],
    evidenceHashes: [],
    chainOfCustody: [
      {
        id: 'COC-301',
        timestamp: '2026-09-04 22:45:00 UTC',
        action: 'Initial Detection',
        actor: 'MailTrace AI Engine',
        details: 'Created case for review by Tier 1 SOC team.',
        hash: '228104ba191024cd912e58410294101e'
      }
    ]
  }
];

export const MOCK_THREAT_CLUSTERS: ThreatIntelligenceCluster[] = [
  {
    id: 'CAMP-2026-FIN-RU',
    campaignName: 'Operation GhostInvoice',
    threatActor: 'TA-505 / ShadowFin Group',
    firstSeen: '2026-03-12',
    lastSeen: '2026-09-05',
    targetedSectors: ['Banking & Financial Services', 'Government Contracting', 'Higher Education'],
    originCountries: ['Russia', 'Belarus', 'Kazakhstan'],
    associatedDomains: ['bank-corp-update.com', 'wire-transfer-node.ru', 'swift-settlement-portal.net', 'finance-swift-verify.org'],
    associatedIps: ['185.220.101.42', '194.165.16.88', '91.218.114.205'],
    activeIndicatorCount: 42,
    riskLevel: 'CRITICAL',
    description: 'Sophisticated BEC criminal network specializing in executive impersonation, urgent wire transfer fraud, and domain lookalike registered within 24 hours of attack.'
  },
  {
    id: 'CAMP-2026-M365-RO',
    campaignName: 'Lazarus M365 Harvester',
    threatActor: 'APT-Lazarus-Subgroup',
    firstSeen: '2026-01-20',
    lastSeen: '2026-09-05',
    targetedSectors: ['Enterprise IT', 'Defense', 'Energy & Utilities'],
    originCountries: ['Romania', 'Bulgaria', 'China'],
    associatedDomains: ['m365-security-portal-verify.net', 'microsoft-auth-sso.online', 'azure-mfa-authenticator.com'],
    associatedIps: ['91.240.118.15', '185.100.85.10', '103.253.41.90'],
    activeIndicatorCount: 128,
    riskLevel: 'HIGH',
    description: 'Automated phishing infrastructure deploying reverse proxy frameworks to bypass 2FA authentication tokens and capture corporate SSO credentials.'
  },
  {
    id: 'CAMP-2026-PAYROLL-BR',
    campaignName: 'Operation DepositHijack',
    threatActor: 'FIN-SouthAm-Phishers',
    firstSeen: '2026-06-01',
    lastSeen: '2026-09-04',
    targetedSectors: ['Corporate HR', 'Healthcare', 'Municipalities'],
    originCountries: ['Brazil', 'Colombia'],
    associatedDomains: ['bankcorp-hr-portal.com', 'anonymized-relay.com', 'hr-portal-direct-deposit.info'],
    associatedIps: ['177.129.44.80', '190.217.20.11'],
    activeIndicatorCount: 19,
    riskLevel: 'HIGH',
    description: 'Targeted HR phishing campaigns attempting payroll account routing modification ahead of bi-weekly disbursement dates.'
  }
];

export const MOCK_REPORTS: ForensicReport[] = [
  {
    id: 'REP-2026-901',
    reportNumber: 'FR-2026-0905-BEC-01',
    title: 'Forensic Investigation & Origin Attribution: Executive BEC Wire Fraud (INV-2026-0905-01)',
    type: 'Incident Response',
    caseId: 'CASE-2026-041',
    createdAt: '2026-09-05 11:30:00 UTC',
    analystName: 'Alex Mercer (Lead Cyber Analyst)',
    status: 'Approved',
    summary: 'Technical evidence package detailing origin server IP 185.220.101.42 (Moscow, RU), DKIM spoofing metrics, payload hash SHA256: a68194f5..., and domain correlation to Operation GhostInvoice.',
    evidenceCount: 14,
    digitalSignature: 'SHA256: 8f9b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b'
  },
  {
    id: 'REP-2026-888',
    reportNumber: 'FR-2026-0905-LE-02',
    title: 'Law Enforcement Evidence Submittal: Bulletproof Phishing Domain m365-security-portal-verify.net',
    type: 'Law Enforcement Submittal',
    caseId: 'CASE-2026-039',
    createdAt: '2026-09-05 09:45:00 UTC',
    analystName: 'Elena Vance (Security Specialist)',
    status: 'Submitted',
    summary: 'Standardized evidentiary report formatted for CERT/CC and Interpol cybercrime division regarding Romanian hosting AS39743 Voxility.',
    evidenceCount: 8,
    digitalSignature: 'SHA256: 1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b'
  }
];

export const CHART_DATA_TRENDS = [
  { date: 'Aug 30', Total: 1420, Phishing: 120, BEC: 45, Impersonation: 80, Legitimate: 1175 },
  { date: 'Aug 31', Total: 1680, Phishing: 150, BEC: 62, Impersonation: 95, Legitimate: 1373 },
  { date: 'Sep 01', Total: 1540, Phishing: 110, BEC: 50, Impersonation: 70, Legitimate: 1310 },
  { date: 'Sep 02', Total: 2100, Phishing: 240, BEC: 88, Impersonation: 140, Legitimate: 1632 },
  { date: 'Sep 03', Total: 1980, Phishing: 190, BEC: 75, Impersonation: 110, Legitimate: 1605 },
  { date: 'Sep 04', Total: 2450, Phishing: 310, BEC: 115, Impersonation: 180, Legitimate: 1845 },
  { date: 'Sep 05', Total: 2819, Phishing: 380, BEC: 142, Impersonation: 210, Legitimate: 2087 },
];

export const CHART_DATA_GEOLOCATIONS = [
  { country: 'Russia', count: 482, riskScore: 94 },
  { country: 'Romania', count: 320, riskScore: 88 },
  { country: 'Brazil', count: 245, riskScore: 85 },
  { country: 'China', count: 210, riskScore: 82 },
  { country: 'Nigeria', count: 185, riskScore: 90 },
  { country: 'Netherlands (Proxy)', count: 140, riskScore: 78 },
  { country: 'United States', count: 95, riskScore: 35 },
];
