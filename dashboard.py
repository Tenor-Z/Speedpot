"""
       ....                                               ..                                      s    
   .x888888hx    :                                      dF                                       :8    
  d88888888888hxx   .d``                               '88bu.       .d``                u.      .88    
 8" ... `"*8888%`   @8Ne.   .u        .u         .u    '*88888bu    @8Ne.   .u    ...ue888b    :888ooo 
!  "   ` .xnxx.     %8888:u@88N    ud8888.    ud8888.    ^"*8888N   %8888:u@88N   888R Y888r -*8888888 
X X   .H8888888%:    `888I  888. :888'8888. :888'8888.  beWE "888L   `888I  888.  888R I888>   8888    
X 'hn8888888*"   >    888I  888I d888 '88%" d888 '88%"  888E  888E    888I  888I  888R I888>   8888    
X: `*88888%`     !    888I  888I 8888.+"    8888.+"     888E  888E    888I  888I  888R I888>   8888    
'8h.. ``     ..x8>  uW888L  888' 8888L      8888L       888E  888F  uW888L  888' u8888cJ888   .8888Lu= 
 `88888888888888f  '*88888Nu88P  '8888c. .+ '8888c. .+ .888N..888  '*88888Nu88P   "*888*P"    ^%888*   
  '%8888888888*"   ~ '88888F`     "88888%    "88888%    `"888*""   ~ '88888F`       'Y"         'Y"    
     ^"****""`        888 ^         "YP'       "YP'        ""         888 ^                            
                      *8E                                             *8E                              
                      '8>                                             '8>                              
                       "                                               "                               
---------------------------------------------------------------------------------------------------------
            01010011 01110000 01100101 01100101 01100100 01110000 01101111 01110100
                                        Speedpot
                                Written by Tyler Bifolchi
                                        2024, 2025
---------------------------------------------------------------------------------------------------------
"""
#========================================================================================================
# This is a work in process as an alternative web-based dashboard interface for Speedpot built with Streamlit. 
# It provides a browser-based visualization and management interface that runs separately from the main Tkinter GUI.
# There are still issues with this interface and such will be a primary point of focus in later updates
#========================================================================================================

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import time
from database_manager import DatabaseManager    # Uses the Database Manager to obtain information
import json

# Page configuration

st.set_page_config(
    page_title="Honeypot Security Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
# Got indecisive

st.markdown("""
    <style>
    .main {
        padding: 0rem 1rem;
    }
    .stMetric {
        background-color: #f0f2f6;
        padding: 15px;
        border-radius: 10px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .threat-critical {
        color: #ff4444;
        font-weight: bold;
    }
    .threat-high {
        color: #ff8800;
        font-weight: bold;
    }
    .threat-medium {
        color: #ffbb33;
    }
    .threat-low {
        color: #00C851;
    }
    .stAlert {
        padding: 1rem;
        border-radius: 0.5rem;
    }
    </style>
""", unsafe_allow_html=True)

# Initialize database

@st.cache_resource
def get_database():
    return DatabaseManager()

db = get_database()

# Sidebar configuration
# I don't like how it looks, but for now, it should suffice

st.sidebar.title("🛡️ Honeypot Control Center")
st.sidebar.markdown("---")

# Time range selector

time_range = st.sidebar.selectbox(
    "Time Range",
    ["Last Hour", "Last 6 Hours", "Last 24 Hours", "Last 7 Days", "Last 30 Days"],
    index=2
)

time_mapping = {
    "Last Hour": 1,
    "Last 6 Hours": 6,
    "Last 24 Hours": 24,
    "Last 7 Days": 168,
    "Last 30 Days": 720
}
hours = time_mapping[time_range]

# Auto-refresh toggle

auto_refresh = st.sidebar.checkbox("Auto-refresh (30s)", value=True)
if auto_refresh:
    st.sidebar.info("Dashboard will refresh every 30 seconds")

# Manual refresh button

if st.sidebar.button("🔄 Refresh Now"):
    st.rerun()

st.sidebar.markdown("---")

# IP Management Section

st.sidebar.subheader("🚫 IP Management")

# Block IP form

with st.sidebar.expander("Block IP Address"):
    block_ip = st.text_input("IP Address to Block")
    block_reason = st.text_input("Reason", value="Manual block")
    block_duration = st.number_input("Duration (hours, 0=permanent)", min_value=0, value=24)
    
    if st.button("Block IP"):
        if block_ip:
            duration = block_duration if block_duration > 0 else None
            if db.block_ip(block_ip, block_reason, duration, auto_blocked=False):
                st.success(f"✅ Blocked {block_ip}")
                db.log_system_event("IP_BLOCKED", "INFO", f"Manually blocked {block_ip}", block_reason, block_ip)
                time.sleep(1)
                st.rerun()
            else:
                st.error("Failed to block IP") # Could already be blocked

# Unblock IP form

with st.sidebar.expander("Unblock IP Address"):
    unblock_ip = st.text_input("IP Address to Unblock")
    
    if st.button("Unblock IP"):
        if unblock_ip:
            if db.unblock_ip(unblock_ip):
                st.success(f"✅ Unblocked {unblock_ip}")
                db.log_system_event("IP_UNBLOCKED", "INFO", f"Manually unblocked {unblock_ip}", None, unblock_ip)
                time.sleep(1)
                st.rerun()
            else:
                st.error("IP not found in blocklist")

st.sidebar.markdown("---")  # Manual markdown for now

# Data cleanup

with st.sidebar.expander("⚙️ Maintenance"):
    cleanup_days = st.number_input("Delete data older than (days)", min_value=1, value=30)
    if st.button("🗑️ Cleanup Old Data"):
        with st.spinner("Cleaning up..."):
            result = db.cleanup_old_data(cleanup_days)
            st.success(f"Deleted: {result.get('connections_deleted', 0)} connections, "
                      f"{result.get('scans_deleted', 0)} scans")

# Main dashboard

st.title("🛡️ Honeypot Security Dashboard")
st.markdown(f"**Monitoring Period:** {time_range} | **Last Updated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

# Get statistics

stats = db.get_statistics(hours)

# Top metrics row

col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.metric(
        label="Total Connections",
        value=f"{stats.get('total_connections', 0):,}",
        delta=None
    )

with col2:
    st.metric(
        label="Unique IPs",
        value=f"{stats.get('unique_ips', 0):,}",
        delta=None
    )

with col3:
    st.metric(
        label="Malicious IPs",
        value=f"{stats.get('malicious_ips', 0):,}",
        delta=None
    )

with col4:
    st.metric(
        label="Port Scans Detected",
        value=f"{stats.get('port_scans', 0):,}",
        delta=None
    )

with col5:
    st.metric(
        label="Blocked IPs",
        value=f"{stats.get('blocked_ips', 0):,}",
        delta=None
    )

st.markdown("---")

# Threat level distribution
# A more graphical approach

threat_levels = stats.get('threat_levels', {})
if threat_levels:
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("🎯 Threat Level Distribution")
        
        # Create pie chart
        threat_df = pd.DataFrame(list(threat_levels.items()), columns=['Threat Level', 'Count'])
        
        color_map = {
            'CRITICAL': '#ff4444',
            'HIGH': '#ff8800',
            'MEDIUM': '#ffbb33',
            'LOW': '#00C851',
            'UNKNOWN': '#999999'
        }
        
        fig = px.pie(
            threat_df,
            values='Count',
            names='Threat Level',
            color='Threat Level',
            color_discrete_map=color_map,
            hole=0.4
        )
        fig.update_traces(textposition='inside', textinfo='percent+label')
        fig.update_layout(height=350)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("📊 Threat Summary")
        for level, count in sorted(threat_levels.items(), key=lambda x: x[1], reverse=True):
            threat_class = f"threat-{level.lower()}"
            st.markdown(f"<div class='{threat_class}'>{level}: {count:,}</div>", unsafe_allow_html=True)
            st.progress(count / stats.get('total_connections', 1))

st.markdown("---")

# Recent connections and top attackers

col1, col2 = st.columns(2)

with col1:
    st.subheader("🔴 Top Attacking IPs")
    top_attackers = stats.get('top_attackers', [])
    
    if top_attackers:
        attacker_df = pd.DataFrame(top_attackers, columns=['IP Address', 'Attempts'])
        
        fig = px.bar(
            attacker_df,
            x='Attempts',
            y='IP Address',
            orientation='h',
            color='Attempts',
            color_continuous_scale='Reds'
        )
        fig.update_layout(height=400, showlegend=False)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No attack data available for this time period")

with col2:
    st.subheader("🚫 Currently Blocked IPs")
    blocked_ips = db.get_blocked_ips()
    
    if blocked_ips:
        blocked_df = pd.DataFrame(blocked_ips)
        blocked_df['blocked_at'] = pd.to_datetime(blocked_df['blocked_at'])
        
        # Display as table with actions

        for idx, row in blocked_df.head(10).iterrows():
            col_a, col_b, col_c = st.columns([3, 2, 1])
            with col_a:
                st.text(f"🔴 {row['ip_address']}")
            with col_b:
                st.text(f"Score: {row['threat_score']}")
            with col_c:
                if st.button("Unblock", key=f"unblock_{idx}"):
                    db.unblock_ip(row['ip_address'])
                    st.rerun()
    else:
        st.info("No IPs currently blocked")

st.markdown("---")

# Recent connections table

st.subheader("📡 Recent Connection Attempts")

connections = db.get_recent_connections(limit=100)

if connections:
    conn_df = pd.DataFrame(connections)
    conn_df['timestamp'] = pd.to_datetime(conn_df['timestamp'])
    
    # Add color coding based on threat level

    def color_threat_level(val):
        colors = {
            'CRITICAL': 'background-color: #ff4444; color: white',
            'HIGH': 'background-color: #ff8800; color: white',
            'MEDIUM': 'background-color: #ffbb33',
            'LOW': 'background-color: #00C851; color: white',
            'UNKNOWN': 'background-color: #999999; color: white'
        }
        return colors.get(val, '')
    
    # Filter options

    col1, col2, col3 = st.columns(3)
    
    with col1:
        threat_filter = st.multiselect(
            "Filter by Threat Level",
            options=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'],
            default=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
        )
    
    with col2:
        show_malicious_only = st.checkbox("Show Malicious Only", value=False)
    
    with col3:
        show_scans_only = st.checkbox("Show Port Scans Only", value=False)
    
    # Apply filters

    filtered_df = conn_df[conn_df['threat_level'].isin(threat_filter)]
    
    if show_malicious_only:
        filtered_df = filtered_df[filtered_df['is_malicious'] == 1]
    
    if show_scans_only:
        filtered_df = filtered_df[filtered_df['scan_detected'] == 1]
    
    # Display table

    display_columns = ['timestamp', 'ip_address', 'port', 'protocol', 'threat_level', 
                      'threat_score', 'country_code', 'is_malicious', 'scan_detected']
    
    styled_df = filtered_df[display_columns].style.applymap(
        color_threat_level,
        subset=['threat_level']
    )
    
    st.dataframe(
        styled_df,
        use_container_width=True,
        height=400
    )
    
    # Export option
    # This will be added soon (hint, hint)

    if st.button("📥 Export to CSV"):
        csv = filtered_df.to_csv(index=False)
        st.download_button(
            label="Download CSV",
            data=csv,
            file_name=f"honeypot_connections_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
else:
    st.info("No connection data available")

st.markdown("---")

# Connection timeline

st.subheader("📈 Connection Timeline")

if connections:
    timeline_df = pd.DataFrame(connections)
    timeline_df['timestamp'] = pd.to_datetime(timeline_df['timestamp'])
    timeline_df['hour'] = timeline_df['timestamp'].dt.floor('H')
    
    # Group by hour and threat level

    timeline_grouped = timeline_df.groupby(['hour', 'threat_level']).size().reset_index(name='count')
    
    fig = px.line(
        timeline_grouped,
        x='hour',
        y='count',
        color='threat_level',
        color_discrete_map={
            'CRITICAL': '#ff4444',
            'HIGH': '#ff8800',
            'MEDIUM': '#ffbb33',
            'LOW': '#00C851',
            'UNKNOWN': '#999999'
        },
        labels={'hour': 'Time', 'count': 'Connection Attempts', 'threat_level': 'Threat Level'}
    )
    fig.update_layout(height=400, hovermode='x unified')
    st.plotly_chart(fig, use_container_width=True)
else:
    st.info("No timeline data available")

st.markdown("---")

# Port scan details

st.subheader("🔍 Port Scan Detection Details")

# Get port scan data from database

try:
    import sqlite3
    conn = sqlite3.connect(db.db_path)
    cursor = conn.cursor()
    
    cutoff_time = (datetime.now() - timedelta(hours=hours)).isoformat()
    cursor.execute('''
        SELECT ip_address, scan_type, ports_scanned, total_attempts,
               time_window_seconds, first_attempt, last_attempt, threat_level,
               ports_list, success_rate
        FROM port_scans
        WHERE first_attempt >= ?
        ORDER BY first_attempt DESC
        LIMIT 50
    ''', (cutoff_time,))
    
    port_scans = cursor.fetchall()
    conn.close()
    
    if port_scans:
        scan_data = []
        for scan in port_scans:
            scan_data.append({
                'IP Address': scan[0],
                'Scan Type': scan[1],
                'Ports Scanned': scan[2],
                'Total Attempts': scan[3],
                'Time Window (s)': scan[4],
                'First Attempt': scan[5],
                'Last Attempt': scan[6],
                'Threat Level': scan[7],
                'Success Rate': f"{scan[9]*100:.1f}%"
            })
        
        scan_df = pd.DataFrame(scan_data)
        st.dataframe(scan_df, use_container_width=True, height=300)
    else:
        st.info("No port scans detected in this time period")
        
except Exception as e:
    st.error(f"Error loading port scan data: {e}")

# Auto-refresh logic

if auto_refresh:
    time.sleep(30)
    st.rerun()
