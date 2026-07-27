import re
import pandas as pd
import numpy as np
from scipy.sparse import hstack
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report, ConfusionMatrixDisplay
import matplotlib.pyplot as plt

phishing_emails = [
    "Dear customer, your account has been suspended. Click here to verify your account now http://bit.ly/verify123",
    "URGENT: Your PayPal account will be locked. Login here to confirm your password http://paypal-secure-login.com",
    "Congratulations! You have won a $1000 gift card. Claim your prize now at http://free-gift-claim.net",
    "Your bank account has suspicious activity. Verify your identity immediately http://secure-bank-verify.com",
    "Action required: update your billing information or your account will be closed http://update-billing-now.com",
    "We noticed a login attempt from a new device. Click here to secure your account http://account-secure123.com",
    "Your package could not be delivered. Confirm your address here http://delivery-confirm.info",
    "Final notice: your subscription payment failed, click to update your card http://payment-update-fast.com",
    "Verify your email now to avoid permanent account suspension http://verify-email-now.biz",
    "You have a pending refund of $250, click below to claim it http://claim-refund-now.com",
    "Security Alert: unusual sign in detected, reset your password immediately http://reset-password-alert.com",
    "Your Netflix account is on hold, update payment details now http://netflix-update-payment.com",
    "IRS Notice: you owe back taxes, pay now to avoid legal action http://irs-payment-portal.net",
    "Your Apple ID has been locked for security reasons, click to unlock http://apple-id-unlock.com",
    "Dear user, click here to confirm your bank details or lose access to your account http://bank-confirm-details.com",
    "Amazon order issue detected, verify your payment method now http://amazon-verify-payment.com",
    "Your email storage is full, click here to upgrade for free http://mail-storage-upgrade.com",
    "Attention: your invoice is overdue, click to make payment immediately http://invoice-payment-now.com",
    "Congratulations winner! You were selected for a free iPhone, claim now http://free-iphone-claim.com",
    "Your account password will expire today, click here to keep access http://password-expire-now.com",
    "We detected malware on your device, click here to run a free scan http://free-virus-scan-now.com",
    "Your social security number has been suspended due to suspicious activity http://ssn-verify-now.com",
    "HR Notice: click here to review your updated salary details http://hr-salary-update.com",
    "Your Facebook account has been reported, verify your identity to avoid ban http://facebook-verify-now.com",
    "Unusual purchase detected on your card, click to dispute the charge http://dispute-charge-now.com",
    "Your domain registration is expiring, renew now to avoid losing your website http://domain-renew-now.com",
    "You have 1 new voicemail, click to listen now http://voicemail-listen-now.com",
    "Your Microsoft account storage limit reached, click to upgrade http://microsoft-storage-upgrade.com",
    "Warning: your antivirus has expired, click here to renew protection http://antivirus-renew-now.com",
    "Your online banking access has been restricted, click to restore access http://restore-bank-access.com",
]

safe_emails = [
    "Hi team, just a reminder that our weekly meeting is moved to 3 PM tomorrow.",
    "Hey mom, I landed safely, will call you once I reach the hotel.",
    "Thanks for the great presentation today, the slides looked really clean.",
    "Here is the report you asked for, let me know if you need any changes.",
    "Lunch on Friday sounds great, see you at the usual place at noon.",
    "The project deadline has been extended to next Monday, please plan accordingly.",
    "Happy birthday! Hope you have an amazing day surrounded by good people.",
    "Attached is the invoice for last month's consulting work, thank you for your business.",
    "Just checking in to see how the new apartment is working out for you.",
    "Reminder: the gym class starts at 6 AM, don't forget your water bottle.",
    "Your order has been shipped and should arrive within 3 to 5 business days.",
    "Great catching up with you at the conference, let's stay in touch.",
    "The quarterly numbers look good, revenue is up 12 percent from last quarter.",
    "Can you send me the notes from today's stand up meeting when you get a chance.",
    "Looking forward to seeing everyone at the family reunion next month.",
    "The book you recommended was fantastic, I finished it in two days.",
    "Please review the attached document and share your feedback by Thursday.",
    "Our flight got delayed by an hour but we should still make the connection.",
    "Thank you for your application, we would like to schedule an interview.",
    "The weather this weekend looks perfect for a hike, are you free Saturday?",
    "Your subscription renewal was successful, thank you for staying with us.",
    "Just a heads up, the office will be closed on Monday for the holiday.",
    "I really enjoyed dinner last night, we should do that again soon.",
    "The new software update improves battery life significantly on most devices.",
    "Congrats on the new job, wishing you all the best in the new role!",
    "Here are the photos from the trip, let me know your favorites.",
    "Reminder that the parent teacher meeting is scheduled for next Wednesday.",
    "Our team hit the sales target this month, great work everyone.",
    "I finished reading your draft, overall it looks solid with a few small edits.",
    "See you at the game this weekend, I'll bring the snacks.",
]

emails = phishing_emails + safe_emails
labels = [1] * len(phishing_emails) + [0] * len(safe_emails)
df = pd.DataFrame({"email_text": emails, "label": labels})

words = ["verify", "urgent", "password", "click here", "suspended", "confirm",
         "account", "bank", "login", "winner", "free", "claim", "act now",
         "security", "update", "restricted"]

def get_features(text):
    urls = len(re.findall(r"http[s]?://\S+", text))
    sus = sum(w in text.lower() for w in words)
    excl = text.count("!")
    return [urls, sus, excl, len(text)]

df[["url_count", "suspicious_word_count", "exclamation_count", "email_length"]] = df["email_text"].apply(get_features).tolist()

vectorizer = CountVectorizer(stop_words="english")
text_features = vectorizer.fit_transform(df["email_text"])
extra_features = df[["url_count", "suspicious_word_count", "exclamation_count", "email_length"]].values
X = hstack([text_features, extra_features])
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42)

model = MultinomialNB()
model.fit(X_train, y_train)
predictions = model.predict(X_test)

print(f"Accuracy: {accuracy_score(y_test, predictions) * 100:.2f}%")
print(classification_report(y_test, predictions, target_names=["Safe", "Phishing"]))

cm = confusion_matrix(y_test, predictions)
print(cm)

ConfusionMatrixDisplay(cm, display_labels=["Safe", "Phishing"]).plot(cmap="Blues")
plt.title("Phishing Email Detector - Confusion Matrix")
plt.tight_layout()
plt.savefig("confusion_matrix.png")

def predict_email(text):
    vec = vectorizer.transform([text])
    extra = np.array([get_features(text)])
    result = model.predict(hstack([vec, extra]))[0]
    return "Phishing" if result == 1 else "Safe"

print(predict_email("Your account has been suspended, click here to verify now http://fake-bank-login.com"))
print(predict_email("Hey, are we still on for coffee tomorrow morning?"))
