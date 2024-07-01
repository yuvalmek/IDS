from scapy.all import sniff, conf

# List all available network interfaces with descriptions
interfaces = conf.ifaces
print("Available interfaces:")
for i in interfaces:
    print(f"{i}: {interfaces[i].description}")

# Prompt the user to enter the index of the Wi-Fi interface
wifi_index = input("Enter the index of the Wi-Fi interface from the list above: ")

# Validate the input and sniff on the selected interface
try:
    wifi_index = int(wifi_index)
    wifi_interface = interfaces[wifi_index].name
    print(f"Monitoring Wi-Fi network on interface: {wifi_interface}")


    # Define a callback function to process packets
    def packet_callback(packet):
        print(packet.summary())


    # Start sniffing on the identified Wi-Fi network interface
    sniff(iface=wifi_interface, prn=packet_callback, count=10)

except (ValueError, KeyError):
    print("Invalid interface index. Please rerun the script and enter a valid index.")
