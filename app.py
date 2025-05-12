import streamlit as st
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import time
from datetime import datetime
import os
import json
from model import RLModel
from dpi_engine import DPIEngine
from packet_analyzer import PacketAnalyzer
from simulator import NetworkSimulator
from utils import load_model, save_model, update_detection_history

# Page configuration
st.set_page_config(
    page_title="NIDS - Network Intrusion Detection System",
    page_icon="🛡️",
    layout="wide",
)

# Initialize session state for storing application state
if 'initialized' not in st.session_state:
    st.session_state.initialized = False
    st.session_state.model = None
    st.session_state.simulator = None
    st.session_state.dpi_engine = None
    st.session_state.packet_analyzer = None
    st.session_state.detection_history = []
    st.session_state.pending_alerts = []
    st.session_state.retraining_needed = False
    st.session_state.feedback_data = []
    st.session_state.running = False
    st.session_state.model_metrics = {
        "precision": 0,
        "recall": 0,
        "f1": 0,
        "accuracy": 0,
        "false_positive_rate": 0
    }
    st.session_state.monitoring = {
        "packets_processed": 0,
        "alerts_generated": 0,
        "admin_confirmed": 0,
        "admin_rejected": 0,
        "retraining_count": 0,
    }

# Initialize the system components if not already done
def initialize_system():
    if not st.session_state.initialized:
        with st.spinner("Initializing NIDS components..."):
            # Initialize the RL model
            st.session_state.model = RLModel()
            
            # Initialize the DPI engine
            st.session_state.dpi_engine = DPIEngine()
            
            # Initialize the packet analyzer
            st.session_state.packet_analyzer = PacketAnalyzer(st.session_state.dpi_engine)
            
            # Initialize the network simulator
            st.session_state.simulator = NetworkSimulator()
            
            # Try to load a pre-trained model if it exists
            model_loaded = load_model(st.session_state.model)
            
            if model_loaded:
                st.success("Pre-trained model loaded successfully!")
            else:
                st.warning("No pre-trained model found. Please train a new model.")
                
            st.session_state.initialized = True

# Main application layout
st.title("🛡️ Reinforcement Learning NIDS")
st.markdown("""
This Network Intrusion Detection System (NIDS) uses reinforcement learning to detect malicious network packets.
It incorporates deep packet inspection and an admin feedback loop for continuous improvement.
""")

# Initialize system on app start
initialize_system()

# Create tabs for different functionalities
tab1, tab2, tab3, tab4 = st.tabs([
    "📊 Dashboard", 
    "🚨 Alerts & Feedback", 
    "⚙️ Model Training", 
    "📈 Performance Metrics"
])

with tab1:
    st.header("System Dashboard")
    
    # Controls section
    control_col1, control_col2 = st.columns(2)
    
    with control_col1:
        if not st.session_state.running:
            if st.button("Start Monitoring", type="primary"):
                st.session_state.running = True
                st.rerun()
        else:
            if st.button("Stop Monitoring", type="secondary"):
                st.session_state.running = False
                st.rerun()
    
    with control_col2:
        dpi_enabled = st.checkbox("Enable Deep Packet Inspection", value=True)
        if dpi_enabled:
            st.session_state.dpi_engine.enable()
        else:
            st.session_state.dpi_engine.disable()
    
    # Stats section
    st.subheader("Monitoring Statistics")
    
    # Create a nice dashboard with KPIs
    col1, col2, col3, col4, col5 = st.columns(5)
    
    col1.metric("Packets Processed", st.session_state.monitoring["packets_processed"])
    col2.metric("Alerts Generated", st.session_state.monitoring["alerts_generated"])
    col3.metric("Admin Confirmed", st.session_state.monitoring["admin_confirmed"])
    col4.metric("Admin Rejected", st.session_state.monitoring["admin_rejected"])
    col5.metric("Retraining Count", st.session_state.monitoring["retraining_count"])
    
    # Recent activity chart
    st.subheader("Recent Activity")
    
    if len(st.session_state.detection_history) > 0:
        # Convert detection history to DataFrame for visualization
        history_df = pd.DataFrame(st.session_state.detection_history)
        
        # Create timeline of detections
        if not history_df.empty and 'timestamp' in history_df.columns and 'is_malicious' in history_df.columns:
            history_df['timestamp'] = pd.to_datetime(history_df['timestamp'])
            history_df = history_df.sort_values('timestamp')
            
            # Group by hour and malicious status
            timeline_df = history_df.groupby([pd.Grouper(key='timestamp', freq='1min'), 'is_malicious']).size().reset_index(name='count')
            
            # Create time series chart
            fig = px.line(timeline_df, x='timestamp', y='count', color='is_malicious',
                        title='Packet Detection Timeline (per minute)',
                        labels={'timestamp': 'Time', 'count': 'Number of Packets', 'is_malicious': 'Malicious'},
                        color_discrete_map={True: 'red', False: 'green'})
            
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Waiting for detection data...")
    else:
        st.info("No detection history available yet. Start monitoring to collect data.")

    # Simulate network traffic and processing if monitoring is active
    if st.session_state.running:
        with st.empty():
            for i in range(5):  # Process a batch of packets
                # Simulate packet capture
                packet = st.session_state.simulator.get_next_packet()
                
                # Process the packet
                features = st.session_state.packet_analyzer.extract_features(packet)
                
                # Use the model to predict
                is_malicious, confidence = st.session_state.model.predict(features)
                
                # Update monitoring stats
                st.session_state.monitoring["packets_processed"] += 1
                
                # If malicious, add to pending alerts
                if is_malicious and confidence > 0.7:  # High confidence threshold
                    st.session_state.monitoring["alerts_generated"] += 1
                    alert_id = f"alert_{int(time.time())}_{st.session_state.monitoring['alerts_generated']}"
                    
                    alert_data = {
                        "id": alert_id,
                        "timestamp": datetime.now().isoformat(),
                        "packet": packet,
                        "features": features.tolist() if isinstance(features, np.ndarray) else features,
                        "confidence": float(confidence),
                        "status": "pending"  # pending, confirmed, rejected
                    }
                    
                    st.session_state.pending_alerts.append(alert_data)
                
                # Update detection history
                update_detection_history(
                    st.session_state.detection_history,
                    packet, 
                    features, 
                    is_malicious,
                    confidence
                )
                
                # Sleep a bit to simulate real-time processing
                time.sleep(0.1)
            
            st.rerun()  # Rerun to update the UI

with tab2:
    st.header("Alerts & Admin Feedback")
    
    if len(st.session_state.pending_alerts) > 0:
        st.warning(f"⚠️ You have {len(st.session_state.pending_alerts)} pending alerts that require your attention.")
        
        for i, alert in enumerate(st.session_state.pending_alerts):
            with st.expander(f"Alert #{i+1} - {alert['timestamp']} (Confidence: {alert['confidence']:.2f})", expanded=i==0):
                # Display packet information
                packet = alert['packet']
                st.json(packet)
                
                # Display packet features used for detection
                st.subheader("Extracted Features")
                st.write(alert['features'])
                
                # Admin feedback controls
                col1, col2 = st.columns(2)
                
                with col1:
                    if st.button("✅ Confirm Malicious", key=f"confirm_{alert['id']}"):
                        st.session_state.monitoring["admin_confirmed"] += 1
                        alert['status'] = "confirmed"
                        
                        # Add to feedback data for retraining
                        st.session_state.feedback_data.append({
                            "features": alert['features'],
                            "label": 1,  # 1 for malicious
                            "timestamp": datetime.now().isoformat()
                        })
                        
                        st.session_state.retraining_needed = True
                        st.success("Alert confirmed as malicious. Model will be retrained.")
                        st.rerun()
                
                with col2:
                    if st.button("❌ Reject (False Positive)", key=f"reject_{alert['id']}"):
                        st.session_state.monitoring["admin_rejected"] += 1
                        alert['status'] = "rejected"
                        
                        # Add to feedback data for retraining
                        st.session_state.feedback_data.append({
                            "features": alert['features'],
                            "label": 0,  # 0 for benign
                            "timestamp": datetime.now().isoformat()
                        })
                        
                        st.session_state.retraining_needed = True
                        st.success("Alert rejected as false positive. Model will be retrained.")
                        st.rerun()
        
        # Remove processed alerts
        st.session_state.pending_alerts = [alert for alert in st.session_state.pending_alerts if alert['status'] == "pending"]
    else:
        st.success("No pending alerts. System is monitoring the network.")
    
    # Feedback history
    st.subheader("Recent Feedback History")
    
    if len(st.session_state.feedback_data) > 0:
        feedback_df = pd.DataFrame(st.session_state.feedback_data)
        feedback_df['timestamp'] = pd.to_datetime(feedback_df['timestamp'])
        feedback_df['type'] = feedback_df['label'].map({0: 'Benign (Rejected)', 1: 'Malicious (Confirmed)'})
        
        # Show feedback timeline
        fig = px.scatter(feedback_df, x='timestamp', y='type', color='type',
                       title='Admin Feedback Timeline',
                       labels={'timestamp': 'Time', 'type': 'Feedback Type'})
        
        st.plotly_chart(fig)
        
        # Summary stats
        confirmed = len(feedback_df[feedback_df['label'] == 1])
        rejected = len(feedback_df[feedback_df['label'] == 0])
        
        st.info(f"Total feedback provided: {len(feedback_df)} (Confirmed malicious: {confirmed}, Rejected as benign: {rejected})")
    else:
        st.info("No feedback history available yet.")

with tab3:
    st.header("Model Training & Retraining")
    
    # Initial training section
    st.subheader("Initial Model Training")
    
    train_col1, train_col2 = st.columns(2)
    
    with train_col1:
        dataset_path = st.text_input("CICIoT2023 Dataset Path", value="./data/CICIoT2023.csv")
    
    with train_col2:
        train_ratio = st.slider("Training Data Ratio", min_value=0.6, max_value=0.9, value=0.8, step=0.05)
    
    if st.button("Train New Model", type="primary"):
        with st.spinner("Training new model from CICIoT2023 dataset..."):
            try:
                # This would be handled by importing the training module and calling its functions
                # For now, we'll simulate the training process
                progress_bar = st.progress(0)
                
                for percent_complete in range(0, 101, 10):
                    time.sleep(0.5)  # Simulate training time
                    progress_bar.progress(percent_complete)
                
                # Update model metrics (simulated for now)
                st.session_state.model_metrics = {
                    "precision": 0.92,
                    "recall": 0.89,
                    "f1": 0.90,
                    "accuracy": 0.94,
                    "false_positive_rate": 0.05
                }
                
                # Save the trained model
                save_model(st.session_state.model)
                
                st.success("Model trained successfully!")
            except Exception as e:
                st.error(f"Error during model training: {str(e)}")
    
    # Retraining section
    st.subheader("Model Retraining")
    
    if st.session_state.retraining_needed:
        st.warning("⚠️ Model retraining is recommended based on recent admin feedback.")
    
    if st.button("Retrain Model with Feedback Data"):
        if len(st.session_state.feedback_data) > 0:
            with st.spinner("Retraining model with admin feedback..."):
                try:
                    # This would be handled by the model's retrain method
                    # For now, we'll simulate the retraining process
                    progress_bar = st.progress(0)
                    
                    for percent_complete in range(0, 101, 20):
                        time.sleep(0.3)  # Simulate training time
                        progress_bar.progress(percent_complete)
                    
                    # Update model metrics (simulated for now)
                    # In a real implementation, these would be calculated from the model's performance
                    st.session_state.model_metrics["precision"] += 0.01
                    st.session_state.model_metrics["recall"] += 0.02
                    st.session_state.model_metrics["f1"] += 0.015
                    st.session_state.model_metrics["accuracy"] += 0.005
                    st.session_state.model_metrics["false_positive_rate"] -= 0.01
                    
                    # Ensure metrics stay in valid range
                    for key in ["precision", "recall", "f1", "accuracy"]:
                        st.session_state.model_metrics[key] = min(0.99, st.session_state.model_metrics[key])
                    
                    st.session_state.model_metrics["false_positive_rate"] = max(0.01, st.session_state.model_metrics["false_positive_rate"])
                    
                    # Reset retraining flag
                    st.session_state.retraining_needed = False
                    
                    # Increment retraining count
                    st.session_state.monitoring["retraining_count"] += 1
                    
                    # Save the retrained model
                    save_model(st.session_state.model)
                    
                    st.success("Model retrained successfully with admin feedback!")
                except Exception as e:
                    st.error(f"Error during model retraining: {str(e)}")
        else:
            st.error("No feedback data available for retraining. Provide feedback on alerts first.")

with tab4:
    st.header("Performance Metrics")
    
    # Model performance metrics
    st.subheader("Model Performance")
    
    metrics_col1, metrics_col2, metrics_col3, metrics_col4, metrics_col5 = st.columns(5)
    
    metrics_col1.metric("Precision", f"{st.session_state.model_metrics['precision']:.2f}")
    metrics_col2.metric("Recall", f"{st.session_state.model_metrics['recall']:.2f}")
    metrics_col3.metric("F1 Score", f"{st.session_state.model_metrics['f1']:.2f}")
    metrics_col4.metric("Accuracy", f"{st.session_state.model_metrics['accuracy']:.2f}")
    metrics_col5.metric("False Positive Rate", f"{st.session_state.model_metrics['false_positive_rate']:.2f}")
    
    # Create metrics visualization
    st.subheader("Performance Visualization")
    
    # Create a radar chart for the metrics
    categories = ['Precision', 'Recall', 'F1 Score', 'Accuracy', '1-FPR']
    values = [
        st.session_state.model_metrics['precision'],
        st.session_state.model_metrics['recall'],
        st.session_state.model_metrics['f1'],
        st.session_state.model_metrics['accuracy'],
        1 - st.session_state.model_metrics['false_positive_rate']
    ]
    
    fig = go.Figure()
    
    fig.add_trace(go.Scatterpolar(
        r=values,
        theta=categories,
        fill='toself',
        name='Model Metrics'
    ))
    
    fig.update_layout(
        polar=dict(
            radialaxis=dict(
                visible=True,
                range=[0, 1]
            )
        ),
        showlegend=False
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # System performance metrics
    st.subheader("System Performance")
    
    if len(st.session_state.detection_history) > 0:
        history_df = pd.DataFrame(st.session_state.detection_history)
        
        # Create confusion matrix visualization if we have ground truth
        if 'is_actually_malicious' in history_df.columns and 'is_malicious' in history_df.columns:
            conf_matrix = pd.crosstab(history_df['is_actually_malicious'], history_df['is_malicious'], 
                                    rownames=['Actual'], colnames=['Predicted'], margins=True)
            
            st.write("Confusion Matrix:")
            st.dataframe(conf_matrix)
            
            # Calculate additional metrics
            if len(history_df) > 0:
                tp = len(history_df[(history_df['is_actually_malicious'] == True) & (history_df['is_malicious'] == True)])
                fp = len(history_df[(history_df['is_actually_malicious'] == False) & (history_df['is_malicious'] == True)])
                tn = len(history_df[(history_df['is_actually_malicious'] == False) & (history_df['is_malicious'] == False)])
                fn = len(history_df[(history_df['is_actually_malicious'] == True) & (history_df['is_malicious'] == False)])
                
                detection_rate = tp / (tp + fn) if (tp + fn) > 0 else 0
                false_alarm_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
                
                metrics_col1, metrics_col2 = st.columns(2)
                metrics_col1.metric("Detection Rate", f"{detection_rate:.2f}")
                metrics_col2.metric("False Alarm Rate", f"{false_alarm_rate:.2f}")
    else:
        st.info("Not enough detection data available yet for performance analysis.")
