import tkinter as tk
from tkinter import messagebox

# Initialize tkinter
root = tk.Tk()
root.withdraw()  # Hide the main window

messagebox.showinfo("Anomaly Detected", "Anomaly detected: <description of anomaly>")
