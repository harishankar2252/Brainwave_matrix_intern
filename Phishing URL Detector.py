import re
import tkinter as tk
from tkinter import messagebox, simpledialog

def is_suspicious_url(url):
    """
    Check the URL for phishing characteristics using heuristics.
    """
    # Patterns to detect suspicious characteristics
    ip_based_url = re.compile(r'^(http|https)://(\d{1,3}\.){3}\d{1,3}(:\d+)?(/.*)?$')  # IP-based URLs
    long_url = re.compile(r'^.{75,}$')  # Very long URLs
    special_chars = re.compile(r'[!@#$%^&*(){}|<>\\/]')  # Unusual special characters
    subdomains = re.compile(r'^(http|https)://([a-zA-Z0-9-]+\.){3,}')  # Excessive subdomains
    
    # Heuristic checks
    if ip_based_url.match(url):
        return "Suspicious: The URL uses an IP address instead of a domain name."
    if long_url.match(url):
        return "Suspicious: The URL is unusually long."
    if special_chars.search(url):
        return "Suspicious: The URL contains unusual special characters."
    if subdomains.match(url):
        return "Suspicious: The URL contains excessive subdomains."
    if "@" in url:
        return "Suspicious: The URL contains an '@' symbol which can be used to mislead users."
    if "-" in url.split('//')[-1].split('/')[0]:
        return "Suspicious: The domain name contains hyphens, a common trait of phishing sites."
    
    return "The URL appears to be safe based on these checks."

def scan_url():
    """
    Function triggered when the 'Scan URL' button is clicked.
    """
    url = simpledialog.askstring("Input URL", "Enter the URL to scan:")
    if not url:
        messagebox.showinfo("No Input", "No URL entered for scanning.")
        return
    
    # Perform the scan
    result = is_suspicious_url(url)
    # Display the result
    messagebox.showinfo("Scan Result", f"URL: {url}\n\nResult: {result}")

def create_gui():
    """
    Create the Tkinter interface for the Phishing Link Scanner.
    """
    # Create the main application window
    root = tk.Tk()
    root.title("Phishing Link Scanner")
    root.geometry("400x200")

    # Add a title label
    title_label = tk.Label(root, text="Phishing Link Scanner", font=("Arial", 16))
    title_label.pack(pady=10)

    # Add a description label
    desc_label = tk.Label(root, text="Scan URLs for potential phishing characteristics.", font=("Arial", 10))
    desc_label.pack(pady=5)

    # Add a button to scan URLs
    scan_button = tk.Button(root, text="Scan URL", command=scan_url, font=("Arial", 12), bg="lightblue")
    scan_button.pack(pady=20)

    # Start the Tkinter main loop
    root.mainloop()

# Run the program
if __name__ == "__main__":
    create_gui()
