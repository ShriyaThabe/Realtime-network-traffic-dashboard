import streamlit as st
import pandas as pd
import plotly.express as px
from scapy.all import sniff, IP, TCP, UDP, ICMP
from threading import Thread, Lock
from collections import deque
import time
import logging  
from datetime import datetime
import threading 

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class PacketProcessor:
    """Process and analyze network packets"""

    def __init__(self):
        self.protocol_map = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP'
        }
        self.packet_data = []
        self.start_time = datetime.now()
        self.packet_count = 0
        self.lock = threading.Lock()

    def get_protocol_name(self, protocol_num: int) -> str:
        """Convert protocol number to name"""
        return self.protocol_map.get(protocol_num, f'OTHER({protocol_num})')

    def process_packet(self, packet) -> None:
        """Process a single packet and extract relevant information"""
        try:
            if IP in packet:
                with self.lock:
                    packet_info = {
                        'timestamp': datetime.now(),
                        'source': packet[IP].src,
                        'destination': packet[IP].dst,
                        'protocol': self.get_protocol_name(packet[IP].proto),
                        'size': len(packet),
                        'time_relative': (datetime.now() - self.start_time).total_seconds()
                    }

                    # Add TCP-specific information
                    if TCP in packet:
                        packet_info.update({
                            'src_port': packet[TCP].sport,
                            'dst_port': packet[TCP].dport,
                            'tcp_flags': packet[TCP].flags
                        })

                    # Add UDP-specific information
                    elif UDP in packet:
                        packet_info.update({
                            'src_port': packet[UDP].sport,
                            'dst_port': packet[UDP].dport
                        })

                    self.packet_data.append(packet_info)
                    self.packet_count += 1

                    # Keep only last 10000 packets to prevent memory issues
                    if len(self.packet_data) > 10000:
                        self.packet_data.pop(0)

        except Exception as e:
            logger.error(f"Error processing packet: {str(e)}")

    def get_dataframe(self) -> pd.DataFrame:
        """Convert packet data to pandas DataFrame"""
        with self.lock:
            return pd.DataFrame(self.packet_data)


def create_visualizations(df: pd.DataFrame):
    """Create all dashboard visualizations"""
    if len(df) > 0:
        # Protocol distribution
        protocol_counts = df['protocol'].value_counts()
        fig_protocol = px.pie(
            values=protocol_counts.values,
            names=protocol_counts.index,
            title="Protocol Distribution"
        )
        st.plotly_chart(fig_protocol, use_container_width=True)

        # Packets timeline
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df_grouped = df.groupby(df['timestamp'].dt.floor('S')).size()
        fig_timeline = px.line(
            x=df_grouped.index,
            y=df_grouped.values,
            title="Packets per Second"
        )
        st.plotly_chart(fig_timeline, use_container_width=True)

        # Top source IPs
        top_sources = df['source'].value_counts().head(10)
        fig_sources = px.bar(
            x=top_sources.index,
            y=top_sources.values,
            title="Top Source IP Addresses"
        )
        st.plotly_chart(fig_sources, use_container_width=True)


def start_packet_capture():
    """Start packet capture in a separate thread"""
    processor = PacketProcessor()

    def capture_packets():
        try:
            sniff(prn=processor.process_packet, store=False)
        except Exception as e:
            logger.error(f"Error starting packet capture: {str(e)}")
            st.error(f"Failed to start packet capture: {str(e)}")
            st.info("Note: This application requires root/administrator privileges to capture network packets.")

    capture_thread = threading.Thread(target=capture_packets, daemon=True)
    capture_thread.start()

    return processor


def main():
    """Main function to run the dashboard"""
    st.set_page_config(page_title="Network Traffic Analysis", layout="wide")
    st.title("Real-time Network Traffic Analysis")
    
    st.write("✅ Dashboard started")

    # Add warning about permissions
    st.warning("⚠️ This application requires root/administrator privileges to capture network packets. "
               "Run with 'sudo streamlit run your_app.py' on Linux/Mac or as Administrator on Windows.")

    # Initialize packet processor in session state
    if 'processor' not in st.session_state:
        st.session_state.processor = start_packet_capture()
        st.session_state.start_time = time.time()

    # Create dashboard layout
    col1, col2 = st.columns(2)

    # Get current data
    df = st.session_state.processor.get_dataframe()

    # Display metrics
    with col1:
        st.metric("Total Packets", len(df))
    with col2:
        duration = time.time() - st.session_state.start_time
        st.metric("Capture Duration", f"{duration:.2f}s")

    # Display visualizations
    create_visualizations(df)

    # Display recent packets
    st.subheader("Recent Packets")
    if len(df) > 0:
        st.dataframe(
            df.tail(10)[['timestamp', 'source', 'destination', 'protocol', 'size']],
            use_container_width=True
        )
    else:
        st.info("No packets captured yet. Make sure you have the necessary permissions and network traffic is present.")

    # Add refresh button
    if st.button('Refresh Data'):
        st.rerun()

    # Auto refresh every 5 seconds (optional)
    # Uncomment the lines below for auto-refresh
    # time.sleep(5)
    # st.rerun()


if __name__ == "__main__":
    main()