"""
Seed training data. 1 = phishing, 0 = legitimate.
Includes English + Hinglish/Hindi (Latin-script transliteration) samples so
the classifier isn't blind to India's most common phishing pattern —
Hinglish KYC/bank-suspension scams.

For production: replace with a real corpus (Nazario phishing corpus + Enron
ham for English; collect/label real Hinglish spam reports for the regional
set).
"""

PHISHING_SAMPLES_EN = [
    "Your account has been suspended click here immediately to verify your identity",
    "Urgent action required your password will expire in 24 hours login now",
    "Congratulations you have won a prize claim your reward now limited time offer",
    "Dear customer your bank account has been locked verify your details to unlock",
    "We detected unusual activity on your account confirm your identity now",
    "Your package could not be delivered click the link to reschedule delivery",
    "Final notice your subscription payment failed update your billing information",
    "Security alert someone tried to access your account verify now or lose access",
    "You have received a secure document click here to view and sign immediately",
    "Your PayPal account is limited verify now to avoid permanent suspension",
    "Tax refund pending click here to claim your refund before it expires",
    "IT department password reset required click link within 24 hours or account disabled",
    "Invoice attached please review and confirm payment urgently to avoid penalty",
    "Your Netflix payment was declined update your card details now",
    "Verify your email account will be closed permanently unless you confirm now",
    "Unauthorized login attempt detected click here to secure your account immediately",
    "You've been selected for a special reward claim within 24 hours",
    "Your Microsoft account was accessed from a new device verify identity now",
    "Action required unusual sign in activity confirm your account details",
    "Your files will be deleted click here to restore access to your storage",
]

LEGITIMATE_SAMPLES_EN = [
    "Hi team please find attached the meeting notes from yesterday's discussion",
    "Reminder our project deadline is next Friday let me know if you need help",
    "Thanks for your email I will get back to you by end of day",
    "Please review the attached report and share your feedback when you get a chance",
    "Looking forward to our call tomorrow at 10am let me know if that still works",
    "Here is the invoice for last month's services as requested",
    "The quarterly numbers look good great work everyone on the team",
    "Can you send me the updated slides for tomorrow's presentation",
    "Happy birthday hope you have a wonderful day surrounded by family",
    "Attached is the syllabus for this semester please go through it carefully",
    "Your order has been shipped and will arrive within 3 to 5 business days",
    "Thank you for attending the workshop here are the resources we discussed",
    "Following up on our conversation from last week regarding the project timeline",
    "The office will be closed on Monday for the holiday see you Tuesday",
    "Please find the minutes of the meeting attached for your reference",
    "Great catching up with you today let's plan the next steps for the project",
    "Your subscription renewal receipt is attached for your records",
    "Reminder that the library books are due for return this Friday",
    "The team lunch is scheduled for Friday at 1pm in the main conference room",
    "Thanks again for your help with the presentation it went really well",
]

# Hinglish / Hindi (Latin transliteration) phishing samples — common
# KYC-update, bank-suspension, and lottery scam patterns seen in India
PHISHING_SAMPLES_HI = [
    "Aapka bank account suspend ho jayega turant KYC update karein yahan click karein",
    "Aapka ATM card block ho gaya hai abhi verify karein warna account band ho jayega",
    "Congratulations aapne 25 lakh rupaye jeete hain claim karne ke liye click karein",
    "Aapka SBI account 24 ghante mein band ho jayega KYC complete karein turant",
    "Aapke Paytm account mein suspicious activity dekhi gayi hai abhi verify karein",
    "Aapka parcel deliver nahi ho paya customs fee pay karein is link par",
    "Urgent aapka PAN card link nahi hua hai account band hone se pehle update karein",
    "Aapko income tax refund mila hai claim karne ke liye apni details confirm karein",
    "Aapka electricity bill pending hai turant pay karein warna connection kat jayega",
    "Aapka OTP expire ho raha hai turant is link par jaake verify karein",
]

LEGITIMATE_SAMPLES_HI = [
    "Kal ki meeting ke notes attach kar diye hain kripya check kar lijiye",
    "Aapka order successfully place ho gaya hai 3 se 5 din mein deliver hoga",
    "Dhanyavaad aapke email ke liye main jaldi hi reply karunga",
    "Shukriya workshop mein aane ke liye yeh resources attach hain",
    "Kal ki call ke liye time confirm kar dijiye 10 baje theek rahega",
    "Aapki subscription ki receipt attach hai apne records ke liye",
    "Office Monday ko holiday ke karan band rahega Tuesday ko milte hain",
    "Meeting ke minutes attach kar diye hain reference ke liye dekh lijiye",
]

PHISHING_SAMPLES = PHISHING_SAMPLES_EN + PHISHING_SAMPLES_HI
LEGITIMATE_SAMPLES = LEGITIMATE_SAMPLES_EN + LEGITIMATE_SAMPLES_HI

# Keyword list used by the lightweight Hinglish/Hindi detector (Latin-script
# Hindi words common in scam messages) — supplements langdetect, which is
# unreliable on short romanized Hindi text
HINGLISH_MARKERS = {
    "aapka", "aapke", "aapko", "aapki", "kripya", "turant", "khata",
    "abhi", "yahan", "jeete", "rupaye", "dhanyavaad", "shukriya",
    "hoga", "hai", "karein", "kijiye", "dijiye", "jayega", "gaya",
    "kholo", "warna", "paisa", "lakh", "ghante", "pehle", "milte",
}

# Multi-word Hinglish/English scam phrases surfaced verbatim to the user
# when found, so the language flag comes with concrete evidence instead
# of just a label. Matched case-insensitively as substrings.
SCAM_PHRASES = [
    "ho jayega", "khata band", "account block", "account suspend",
    "click karein", "click karo", "verify karein", "turant update",
    "kyc update", "otp share", "otp batayen", "link par click",
    "abhi verify", "warna account", "24 ghante", "click here immediately",
    "verify your identity", "account has been suspended", "claim your reward",
    "won a prize", "urgent action required", "confirm your identity",
    "avoid permanent suspension", "click here to verify",
]
