import tkinter as tk
from tkinter import ttk
import requests
import pandas as pd
import base64

# This script will run a URL vs VirusTotal's database and report whether it was malicious + save the test results to .csv.
# Depends on Py Libraries: tkinter, pandas, requests, base64
# Note: This API key is for personal use only and must not be used in commercial products or services.
# Usage Limits: 4 lookups per minute, 500 lookups per day, 15.5K lookups per month

api_key = 'YOUR-API-KEY-HERE'
scan_url = 'https://www.virustotal.com/api/v3/urls'
report_url = 'https://www.virustotal.com/api/v3/analyses/{}'
headers = {
    'x-apikey': api_key
}

def scan_url_for_threat(url_to_scan):
    encoded_url = base64.urlsafe_b64encode(url_to_scan.encode()).decode().strip("=")
    response = requests.post(scan_url, headers=headers, data={'url': url_to_scan})
    
    if response.status_code == 200:
        response_json = response.json()
        report_id = response_json.get('data', {}).get('id')
        if report_id:
            report_response = requests.get(report_url.format(report_id), headers=headers)
            if report_response.status_code == 200:
                report_data = report_response.json()
                return report_data
            else:
                print(f"Failed to fetch report: {report_response.status_code}")
        else:
            print("Failed to retrieve report ID.")
    else:
        print(f"Failed to submit URL: {response.status_code}")
    return None

def interpret_results(report_data):
    if not report_data:
        return "Unable to fetch results."

    # Extracting relevant information from the report_data
    attributes = report_data.get('data', {}).get('attributes', {})
    stats = attributes.get('last_analysis_stats', {})
    
    if stats.get('malicious', 0) > 0:
        return "Unsafe - The URL has been flagged as malicious."
    elif stats.get('suspicious', 0) > 0:
        return "Suspicious - The URL has some suspicious flags."
    else:
        return "Safe - No threats detected."

def on_submit():
    url = url_entry.get()
    report_data = scan_url_for_threat(url)
    result = interpret_results(report_data)
    
    if report_data is not None:
        # Save to CSV
        csv_file_path = 'virustotal_report.csv'
        df = pd.json_normalize(report_data)
        df.to_csv(csv_file_path, index=False)
        status_label.config(text=f"Data saved to {csv_file_path}. {result}", foreground="#00FF00")  # Neon green
    else:
        status_label.config(text="Failed to retrieve or save report.", foreground="#FF0000")  # Red

# Set up the main application window
root = tk.Tk()
root.title("URL Scanner")

# Set up the style
style = ttk.Style()
style.configure('TFrame', background='#2E2E2E')  # Dark grey
style.configure('TLabel', background='#2E2E2E', foreground='#00FF00')  # Neon green
style.configure('TEntry', background='#2E2E2E', foreground='#00FF00', fieldbackground='#2E2E2E')
# Configure TButton style
style.configure('TButton',
                background='#2E2E2E',  # Dark grey background (default, as ttk doesn't handle background well)
                foreground='#00FF00')  # Neon green text color
style.map('TButton',
          background=[('pressed', '#1a1a1a'), ('active', '#2a2a2a')])  # Button background changes on interaction

# Create and pack widgets
frame = ttk.Frame(root, style='TFrame', padding="10")
frame.pack(padx=10, pady=10, fill='both', expand=True)

# Create GUI elements
url_label = ttk.Label(frame, text="Enter URL:")
url_label.grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)

url_entry = ttk.Entry(frame, width=50)
url_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5, pady=5)

submit_button = ttk.Button(frame, text="Scan URL", command=on_submit, style='Custom.TButton')
submit_button.grid(row=1, column=0, columnspan=2, pady=10, padx=5)

status_label = ttk.Label(frame, text="Status will be displayed here.", wraplength=400)
status_label.grid(row=2, column=0, columnspan=2, pady=5, padx=5)

# Run the application
root.mainloop()
