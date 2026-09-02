import os
import joblib


# ============================================================
# PATHS
# ============================================================

MODEL_PATH = r"ml\model\email_classifier.pkl"
VECTORIZER_PATH = r"ml\model\tfidf_vectorizer.pkl"


# ============================================================
# LOAD MODEL
# ============================================================

print("Loading MailTrace AI model...")

model = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECTORIZER_PATH)

print("Model loaded successfully.\n")


# ============================================================
# PREDICTION FUNCTION
# ============================================================

def analyze_email(email_text):

    # Convert email text into TF-IDF features
    email_vector = vectorizer.transform([email_text])

    # Prediction
    prediction = model.predict(email_vector)[0]

    # Probability
    probabilities = model.predict_proba(email_vector)[0]

    # Find probability belonging to phishing class
    phishing_index = list(model.classes_).index(1)

    phishing_probability = probabilities[phishing_index]

    # Convert to percentage
    phishing_percentage = phishing_probability * 100

    # Classification
    if phishing_percentage >= 50:
        classification = "PHISHING"
    else:
        classification = "LEGITIMATE"

    return {
        "classification": classification,
        "phishing_probability": round(phishing_percentage, 2)
    }

# ============================================================
# INTERACTIVE EMAIL TEST
# ============================================================

print("========================================")
print("MAILTRACE AI EMAIL ANALYZER")
print("========================================")

print("\nPaste your email below.")
print("When finished, press ENTER and then Ctrl+Z followed by ENTER.")
print("(Windows PowerShell)\n")

lines = []

while True:
    try:
        line = input()
        lines.append(line)
    except EOFError:
        break

email = "\n".join(lines)

result = analyze_email(email)

print("\n========================================")
print("ANALYSIS RESULT")
print("========================================")

print(f"Classification : {result['classification']}")
print(f"Phishing Score : {result['phishing_probability']}%")

print("========================================")

# ============================================================
# RUN ANALYSIS
# ============================================================

result = analyze_email(email)


print("========================================")
print("MAILTRACE AI EMAIL ANALYSIS")
print("========================================")

print(f"\nClassification:")
print(result["classification"])

print(f"\nPhishing Probability:")
print(f'{result["phishing_probability"]}%')

print("\n========================================")