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

    resolutions.sort()

    times = np.array([r[0] for r in resolutions])

    time_elapsed = times - times[0]

    resolution_counts = np.arange(1, len(times) + 1)

    plt.step(time_elapsed, resolution_counts)

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

    times = np.array(times)
    elapsed_time = times - times[0]

    tls_v1_counts = np.array(tls_v1_counts)
    tls_v1_2_counts = np.array(tls_v1_2_counts)
    tls_v1_3_counts = np.array(tls_v1_3_counts)

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

    times = np.array(times)
    elapsed_time = times - times[0]

    handshake_counts = np.array(handshake_counts)

    fig, ax = plt.subplots()
    ax.step(elapsed_time, handshake_counts, label="Client Hello")
    ax.legend()
    ax.set_xlabel("Elapsed Time (s)")
    ax.set_ylabel("Handshake Protocol Usage Count")
    ax.set_title("Handshake Protocol Usage over Time")

    # Show the plot
    plt.show()


def plot_tcp_usage_over_time(file_name):
    capture = pyshark.FileCapture(file_name, display_filter="tcp")

    tcp_count = 0
    tcp_counts = []
    times = []

    first_packet = capture[0]
    last_packet = capture[-1]
    start_time = float(first_packet.sniff_timestamp)
    end_time = float(last_packet.sniff_timestamp)

    for packet in capture:
        tcp_count += 1
        tcp_counts.append(tcp_count)
        times.append(float(packet.sniff_time.timestamp()))
    capture.close()

    times = np.array(times)
    elapsed_time = times - times[0]

    tcp_counts = np.array(tcp_counts)

    fig, ax = plt.subplots()
    ax.step(elapsed_time, tcp_counts)
    ax.legend()
    ax.set_xlabel("Elapsed Time (s)")
    ax.set_ylabel("TCP Protocol Usage Count")
    ax.set_title("TCP Protocol Usage over Time")

    # Show the plot
    plt.show()


def plot_rtcp_usage_over_time(file_name):
    capture = pyshark.FileCapture(file_name, display_filter="rtcp")

    rtcp_count = 0
    rtcp_counts = []
    times = []

    first_packet = capture[0]
    last_packet = capture[-1]
    start_time = float(first_packet.sniff_timestamp)
    end_time = float(last_packet.sniff_timestamp)

    for packet in capture:
        rtcp_count += 1
        rtcp_counts.append(rtcp_count)
        times.append(float(packet.sniff_time.timestamp()))
    capture.close()

    times = np.array(times)
    elapsed_time = times - times[0]

    rtcp_counts = np.array(rtcp_counts)

    fig, ax = plt.subplots()
    ax.step(elapsed_time, rtcp_counts)
    ax.legend()
    ax.set_xlabel("Elapsed Time (s)")
    ax.set_ylabel("RTCP Protocol Usage Count")
    ax.set_title("RTCP Protocol Usage over Time")

    # Show the plot
    plt.show()


def plot_udp_usage_over_time(file_name):
    capture = pyshark.FileCapture(file_name, display_filter="udp")

    udp_count = 0
    udp_counts = []
    times = []

    first_packet = capture[0]
    last_packet = capture[-1]
    start_time = float(first_packet.sniff_timestamp)
    end_time = float(last_packet.sniff_timestamp)

    for packet in capture:
        udp_count += 1
        udp_counts.append(udp_count)
        times.append(float(packet.sniff_time.timestamp()))
    capture.close()

    times = np.array(times)
    elapsed_time = times - times[0]

    udp_counts = np.array(udp_counts)

    fig, ax = plt.subplots()
    ax.step(elapsed_time, udp_counts)
    ax.legend()
    ax.set_xlabel("Elapsed Time (s)")
    ax.set_ylabel("UDP Protocol Usage Count")
    ax.set_title("UDP Protocol Usage over Time")

    # Show the plot
    plt.show()


def plot_quic_usage_over_time(file_name):
    capture = pyshark.FileCapture(file_name, display_filter="quic")

    quic_count = 0
    quic_counts = []
    times = []

    first_packet = capture[0]
    last_packet = capture[-1]
    start_time = float(first_packet.sniff_timestamp)
    end_time = float(last_packet.sniff_timestamp)

    for packet in capture:
        quic_count += 1
        quic_counts.append(quic_count)
        times.append(float(packet.sniff_time.timestamp()))

    capture.close()

    times = np.array(times)
    elapsed_time = times - times[0]

    quic_counts = np.array(quic_counts)

    fig, ax = plt.subplots()
    ax.step(elapsed_time, quic_counts)
    ax.legend()
    ax.set_xlabel("Elapsed Time (s)")
    ax.set_ylabel("QUIC Protocol Usage Count")
    ax.set_title("QUIC Protocol Usage over Time")

    # Show the plot
    plt.show()

