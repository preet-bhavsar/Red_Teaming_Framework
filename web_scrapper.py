import os
import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Function to extract emails from the webpage
def extract_emails(text):
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    return re.findall(email_pattern, text)

# Function to extract emails from mailto links
def extract_emails_from_mailto(soup):
    emails = []
    for a in soup.find_all('a', href=True):
        href = a['href']
        if href.startswith('mailto:'):
            email = href[7:]  # Remove 'mailto:'
            emails.append(email)
    return emails

# Function to extract phone numbers (basic pattern, may need refinement)
def extract_phone_numbers(text):
    phone_pattern = r'\+?\d{1,4}?[-.\s]?\(?\d{2,4}?\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}'
    return re.findall(phone_pattern, text)

# Function to download images
def download_images(url, soup, output_folder="images"):
    os.makedirs(output_folder, exist_ok=True)
    for img_tag in soup.find_all("img"):
        img_url = urljoin(url, img_tag.get("src"))
        img_name = os.path.join(output_folder, os.path.basename(img_url.split("?")[0]))
        try:
            img_data = requests.get(img_url).content
            with open(img_name, "wb") as img_file:
                img_file.write(img_data)
            print(f"Downloaded: {img_name}")
        except Exception as e:
            print(f"Failed to download {img_url}: {e}")

# Ensure the URL has a scheme
def validate_url(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url  # Default to HTTPS
    return url

# Main function to scrape website
def scrape_website(url):
    url = validate_url(url)  # Fix URL before requesting
    headers = {"User-Agent": "Mozilla/5.0"}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()  # Raise an error for bad responses (4xx, 5xx)

        soup = BeautifulSoup(response.text, "html.parser")
        text = soup.get_text()

        emails = extract_emails(response.text) + extract_emails_from_mailto(soup)
        emails = list(set(emails))  # Remove duplicates
        phone_numbers = extract_phone_numbers(response.text)

        # Save emails
        with open("emails.txt", "w") as f:
            f.write("\n".join(emails))
        print("✅ Emails saved in emails.txt")

        # Save phone numbers
        with open("contacts.txt", "w") as f:
            f.write("\n".join(phone_numbers))
        print("✅ Phone numbers saved in contacts.txt")

        # Download images
        download_images(url, soup)

    except requests.exceptions.RequestException as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    target_url = input("Enter the website URL: ").strip()
    scrape_website(target_url)
