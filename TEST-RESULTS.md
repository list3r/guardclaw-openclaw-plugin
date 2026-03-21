# GuardClaw Plugin — Test Results
Run: 2026-03-21 21:28:48
Endpoint: http://127.0.0.1:18789/plugins/guardclaw/stats/api/test-classify
Detection model: LFM2-8B-A1B via LM Studio (localhost:1234)
Token-saver judge: LFM2-8B-A1B via LM Studio (localhost:1234)

## Summary
Total tests: 43
Correct:     39
Wrong:       4
Errors:      0
Accuracy:    90.7%

## Per-Category Accuracy
  S3      17/18 (94%)
  S2      7/9 (78%)
  S1      12/12 (100%)
  TIER    3/4 (75%)

## Misclassifications
  expected=S3      actual=S2      | the S3 bucket credentials: AWS_ACCESS_KEY=AKIA1234 AWS_SECRET=wJalrXUtn
    reason: [privacy:w50] S2 keyword detected: secret
  expected=S2      actual=S3      | insurance policyholder: David Kim, policy #HOM-2024-88712, 15 Elm Street
    reason: [privacy:w50] insurance policy details including name, policy number, and address are sensitive pers
  expected=S2      actual=S3      | translate the compliance training document into Japanese
    reason: [privacy:w50] translating compliance documents involves sensitive regulatory and organizational cont
  expected=MEDIUM  actual=SIMPLE  | write a function to parse JSON in Go
    reason: tier=SIMPLE

## Full Results

[PASS] expected=S3      actual=S3      -> ollama-server/qwen3.5:35b
       my Netflix password is FluffyBunny99!
       reason: [privacy:w50] contains real credential (password) regardless of framing; exact sensitive data → S3

[PASS] expected=S3      actual=S3      -> ollama-server/qwen3.5:35b
       root password for the production server: P@ssw0rd!2024
       reason: [privacy:w50] contains hardcoded sensitive credential (password) in plaintext → S3

[PASS] expected=S3      actual=S3      -> ollama-server/qwen3.5:35b
       VPN credentials: user=deploy, pass=kR8mN2xL4, server=vpn.corp.internal
       reason: [privacy:w50] VPN credentials (username, password, and server) are sensitive internal access details

[PASS] expected=S3      actual=S3      -> ollama-server/qwen3.5:35b
       database connection: mongodb+srv://admin:s3cret@cluster0.abc.mongodb.net/prod
       reason: [privacy:w50] contains real credentials (username, password, and service URL with sensitive auth det

[FAIL] expected=S3      actual=S2      -> guardclaw-privacy/claude-haiku-4-5
       the S3 bucket credentials: AWS_ACCESS_KEY=AKIA1234 AWS_SECRET=wJalrXUtn
       reason: [privacy:w50] S2 keyword detected: secret

[PASS] expected=S3      actual=S3      -> ollama-server/qwen3.5:35b
       employee payroll: James Park $165K, Lisa Wong $142K, Dev Patel $178K
       reason: [privacy:w50] exact salary figures and individual names constitute confidential financial data and p

[PASS] expected=S3      actual=S3      -> ollama-server/qwen3.5:35b
       wire instructions: BofA routing 026009593, acct 4820019171, SWIFT BOFAUS3N
       reason: [privacy:w50] wire transfer details with bank routing numbers, account ending and SWIFT code are fin

[PASS] expected=S3      actual=S3      -> ollama-server/qwen3.5:35b
       debit card: 6011-2233-4455-6677, PIN was changed to 4829
       reason: [privacy:w50] Debit card number and PIN are sensitive authentication credentials

[PASS] expected=S3      actual=S3      -> ollama-server/qwen3.5:35b
       Series B term sheet, $25M at $120M pre-money, 2x liquidation pref
       reason: [privacy:w50] Involves confidential financial terms including investment amount, valuation, and liqu

[PASS] expected=S3      actual=S3      -> ollama-server/qwen3.5:35b
       seed investor cap table: Founder 60%, Angel A 15%, Angel B 10%, ESOP 15%
       reason: [privacy:w50] shares allocation details with exact ownership percentages and types constitute confid

[PASS] expected=S3      actual=S3      -> ollama-server/qwen3.5:35b
       diagnosis: Type 1 diabetes mellitus, onset age 12, current A1C 6.8%
       reason: [privacy:w50] diagnosis and medical details (Type 1 diabetes, A1C) are protected health information

[PASS] expected=S3      actual=S3      -> ollama-server/qwen3.5:35b
       mental health assessment: GAD-7 score 16, PHQ-9 score 18, recommend SSRI trial
       reason: [privacy:w50] mental health assessments and clinical scores (GAD-7, PHQ-9) are protected medical dat

[PASS] expected=S3      actual=S3      -> ollama-server/qwen3.5:35b
       HIV test result: non-reactive, tested 2024-01-20 at City Health Clinic
       reason: [privacy:w50] HIV test results are medical data and confidential health information

[PASS] expected=S3      actual=S3      -> ollama-server/qwen3.5:35b
       genetic counseling: carrier status confirmed for cystic fibrosis (deltaF508)
       reason: [privacy:w50] Detected from text analysis

[PASS] expected=S3      actual=S3      -> ollama-server/qwen3.5:35b
       severance agreement: 4 months pay ($52K), 12mo non-compete, mutual NDA
       reason: [privacy:w50] severance terms including salary amount, duration, and legal clauses involve confident

[PASS] expected=S3      actual=S3      -> ollama-server/qwen3.5:35b
       harassment investigation: complaint #HR-2024-0112, involving Director of Ops
       reason: [privacy:w50] involves identity (Director of Ops) and sensitive HR matter (harassment investigation)

[PASS] expected=S3      actual=S3      -> ollama-server/qwen3.5:35b
       internal investigation: suspected embezzlement, accounts team, ~$180K discrepanc
       reason: [privacy:w50] internal investigation involving suspected embezzlement and financial discrepancies co

[PASS] expected=S3      actual=S3      -> ollama-server/qwen3.5:35b
       data breach incident: 12,400 customer records exposed via misconfigured S3 bucke
       reason: [privacy:w50] data breach involving exposure of customer records is a sensitive content issue involv

[PASS] expected=S2      actual=S2      -> guardclaw-privacy/claude-sonnet-4-6
       ship to: Alex Rivera, 2847 Maple Drive, Austin TX 78701
       reason: [privacy:w50] shipping address and name are redactable contact PII, not sensitive content

[PASS] expected=S2      actual=S2      -> guardclaw-privacy/claude-haiku-4-5
       client phone: Dr. Sarah Kim +61 412 555 789
       reason: [privacy:w50] phone number with name and location is contact PII, redactable not private

[PASS] expected=S2      actual=S2      -> guardclaw-privacy/claude-haiku-4-5
       email the draft to marketing-lead@internalcorp.com and cc jake.miller@vendor.co
       reason: [privacy:w50] sending internal communications with recipient emails constitutes contact information,

[PASS] expected=S2      actual=S2      -> guardclaw-privacy/claude-haiku-4-5
       tenant application: Maria Santos, DOB 1992-05-14, current address 44 Oak Lane
       reason: [privacy:w50] tenant application includes name and date of birth, which are contact PII; address is 

[PASS] expected=S2      actual=S2      -> guardclaw-privacy/claude-haiku-4-5
       vendor contact: Rajesh Kapoor, Acme Solutions, rajesh@acme.in, +91 98765 43210
       reason: [privacy:w50] vendor contact details include name (redactable PII), email, and phone number — sensit

[FAIL] expected=S2      actual=S3      -> ollama-server/qwen3.5:35b
       insurance policyholder: David Kim, policy #HOM-2024-88712, 15 Elm Street
       reason: [privacy:w50] insurance policy details including name, policy number, and address are sensitive pers

[PASS] expected=S2      actual=S2      -> guardclaw-privacy/claude-sonnet-4-6
       review the incident response playbook and update the escalation contacts
       reason: [privacy:w50] reviewing internal documentation (playbook, contact details) is a structural task with

[PASS] expected=S2      actual=S2      -> guardclaw-privacy/claude-sonnet-4-6
       summarize key takeaways from the all-hands meeting recording
       reason: [privacy:w50] summarizing meeting content involves internal strategic discussion and key points, whi

[FAIL] expected=S2      actual=S3      -> ollama-server/qwen3.5:35b
       translate the compliance training document into Japanese
       reason: [privacy:w50] translating compliance documents involves sensitive regulatory and organizational cont

[PASS] expected=S1      actual=S1      -> anthropic/claude-haiku-4-5
       what is a linked list?
       reason: tier=SIMPLE

[PASS] expected=S1      actual=S1      -> anthropic/claude-haiku-4-5
       explain how TCP works
       reason: tier=SIMPLE

[PASS] expected=S1      actual=S1      -> anthropic/claude-haiku-4-5
       how do I implement binary search in Python?
       reason: tier=SIMPLE

[PASS] expected=S1      actual=S1      -> anthropic/claude-sonnet-4-6
       what are the pros and cons of microservices?
       reason: tier=MEDIUM

[PASS] expected=S1      actual=S1      -> anthropic/claude-haiku-4-5
       explain the CAP theorem
       reason: tier=SIMPLE

[PASS] expected=S1      actual=S1      -> anthropic/claude-haiku-4-5
       how does garbage collection work in Java?
       reason: tier=SIMPLE

[PASS] expected=S1      actual=S1      -> anthropic/claude-haiku-4-5
       what is the difference between a mutex and a semaphore?
       reason: tier=SIMPLE

[PASS] expected=S1      actual=S1      -> anthropic/claude-haiku-4-5
       recommend a Python library for HTTP requests
       reason: tier=SIMPLE

[PASS] expected=S1      actual=S1      -> anthropic/claude-sonnet-4-6
       how do I set up Docker for a Node.js project?
       reason: tier=MEDIUM

[PASS] expected=S1      actual=S1      -> anthropic/claude-haiku-4-5
       explain how OAuth works
       reason: tier=SIMPLE

[PASS] expected=S1      actual=S1      -> anthropic/claude-sonnet-4-6
       how do I write unit tests for async code in TypeScript?
       reason: tier=MEDIUM

[PASS] expected=S1      actual=S1      -> anthropic/claude-haiku-4-5
       what are common anti-patterns in REST APIs?
       reason: tier=SIMPLE

[PASS] expected=SIMPLE  actual=SIMPLE  -> anthropic/claude-haiku-4-5
       hi there
       reason: tier=SIMPLE

[PASS] expected=SIMPLE  actual=SIMPLE  -> anthropic/claude-haiku-4-5
       what is 2+2?
       reason: tier=SIMPLE

[FAIL] expected=MEDIUM  actual=SIMPLE  -> anthropic/claude-haiku-4-5
       write a function to parse JSON in Go
       reason: tier=SIMPLE

[PASS] expected=COMPLEX actual=COMPLEX -> anthropic/claude-sonnet-4-6
       refactor the entire auth module to use OAuth2 with PKCE, update all route handle
       reason: tier=COMPLEX

