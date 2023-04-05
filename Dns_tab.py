import matplotlib.pyplot as plt
import numpy as np
import pyshark


def dns_resolution_evolution(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
        num_resolutions = int(lines[0].split()[-1])
        resolutions = []
        for line in lines[1:]:
            line_parts = line.strip().split()
            domain = ' '.join(line_parts[1:-2])
            time_str = line_parts[-1]
            time_str_tab = time_str.split(':')
            if len(time_str_tab) >= 3:
                time = float(time_str_tab[1]) * 60 + float(time_str_tab[2])
            else:
                continue
            resolutions.append((time, domain))

    # Sort resolutions by time
    resolutions.sort()

    # Convert the list of times to a NumPy array
    times = np.array([r[0] for r in resolutions])

    # Compute the elapsed time between the first resolution and each subsequent resolution
    time_elapsed = times - times[0]

    # Create a list of the number of resolutions at each time point
    resolution_counts = np.arange(1, len(times) + 1)

    # Plot the resolution counts vs. time elapsed
    plt.step(time_elapsed, resolution_counts)

    # Add axis labels and title
    plt.xlabel('Time Elapsed (s)')
    plt.ylabel('Number of DNS Resolutions')
    plt.title('Evolution of DNS Resolutions over Time')

    # Show the plot
    plt.show()


def plot_tls_protocol_usage_over_time(file_path):
    capture = pyshark.FileCapture(file_path, display_filter="tls")

    tls_v1_count = 0
    tls_v1_2_count = 0
    tls_v1_3_count = 0
    tls_v1_counts = []
    tls_v1_2_counts = []
    tls_v1_3_counts = []
    times = []

    for packet in capture:
        try:
            print(packet.tls.handshake.certificate)
            tls = str(packet.tls)
            handshake = str(packet.tls.handshake)
            if "TLSv1.3" in tls and "Client Hello" in handshake:
                tls_v1_3_count += 1
                tls_v1_3_counts.append(tls_v1_3_count)
                tls_v1_2_counts.append(tls_v1_2_count)
                tls_v1_counts.append(tls_v1_count)
            elif "TLSv1.2" in tls and "Client Hello" in handshake:
                tls_v1_2_count += 1
                tls_v1_3_counts.append(tls_v1_3_count)
                tls_v1_2_counts.append(tls_v1_2_count)
                tls_v1_counts.append(tls_v1_count)
            elif "TLSv1" in tls and "Client Hello" in handshake:
                tls_v1_count += 1
                tls_v1_3_counts.append(tls_v1_3_count)
                tls_v1_2_counts.append(tls_v1_2_count)
                tls_v1_counts.append(tls_v1_count)
            else:
                continue

            times.append(float(packet.sniff_time.timestamp()))
        except AttributeError:
            continue

    capture.close()

    # Convert the list of times to a NumPy array and subtract the first time to obtain elapsed time
    times = np.array(times)
    elapsed_time = times - times[0]

    # Create NumPy arrays of the protocol counts for each version
    tls_v1_counts = np.array(tls_v1_counts)
    tls_v1_2_counts = np.array(tls_v1_2_counts)
    tls_v1_3_counts = np.array(tls_v1_3_counts)

    # Create a plot of the protocol counts vs. elapsed time
    fig, ax = plt.subplots()
    ax.step(elapsed_time, tls_v1_counts, label="TLSv1")
    ax.step(elapsed_time, tls_v1_2_counts, label="TLSv1.2")
    ax.step(elapsed_time, tls_v1_3_counts, label="TLSv1.3")
    ax.legend()
    ax.set_xlabel("Elapsed Time (s)")
    ax.set_ylabel("Protocol Usage Count")
    ax.set_title("TLS Protocol Usage over Time")

    # Show the plot
    plt.show()


def handshake_usage_over_time(file_path):
    capture = pyshark.FileCapture(file_path, display_filter="tls")

    handshake_count = 0
    handshake_counts = []
    times = []

    for packet in capture:
        try:

            tls = str(packet.tls.handshake)
            if "Server Hello" in tls:
                handshake_count += 1
                handshake_counts.append(handshake_count)
            else:
                continue

            times.append(float(packet.sniff_time.timestamp()))
        except AttributeError:
            continue

    capture.close()

    # Convert the list of times to a NumPy array and subtract the first time to obtain elapsed time
    times = np.array(times)
    elapsed_time = times - times[0]

    # Create NumPy arrays of the protocol counts for each version
    handshake_counts = np.array(handshake_counts)

    # Create a plot of the protocol counts vs. elapsed time
    fig, ax = plt.subplots()
    ax.step(elapsed_time, handshake_counts, label="Client Hello")
    ax.legend()
    ax.set_xlabel("Elapsed Time (s)")
    ax.set_ylabel("Handshake Protocol Usage Count")
    ax.set_title("Handshake Protocol Usage over Time")

    # Show the plot
    plt.show()


plot_tls_protocol_usage_over_time('Teams_Complet.pcapng')
