import dash
from dash import dcc, html, Input, Output
import plotly.graph_objs as go
import pandas as pd
import logging

logger = logging.getLogger(__name__)


class SecurityDashboard:

    def __init__(self, packet_data=None, alerts=None, data_callback=None):
        self.df = packet_data if packet_data is not None else pd.DataFrame()
        self.alerts = alerts if alerts is not None else []
        self.data_callback = data_callback  # callable returning (df, alerts) for live updates
        self.app = dash.Dash(__name__)
        self._setup_layout()
        self._setup_callbacks()

    def _setup_layout(self):
        self.app.layout = html.Div([
            html.Div([
                html.H1("🛡️ CyberSentinel Dashboard",
                        style={'textAlign': 'center', 'color': '#2c3e50'}),
                html.P("Real-time Network Security Monitoring",
                       style={'textAlign': 'center', 'color': '#7f8c8d'})
            ], style={'padding': '20px', 'backgroundColor': '#ecf0f1'}),

            html.Div(id='stats-row',
                     style={'display': 'flex', 'justifyContent': 'space-around',
                            'padding': '20px'}),

            html.Div([
                html.H2("🚨 Security Alerts", style={'color': '#e74c3c'}),
                html.Div(id='alerts-container')
            ], style={'padding': '20px', 'backgroundColor': '#fff3cd',
                      'margin': '10px', 'borderRadius': '10px'}),

            html.Div([
                dcc.Graph(id='traffic-volume'),
                html.Div([
                    html.Div(dcc.Graph(id='protocol-dist'),
                             style={'width': '48%', 'display': 'inline-block',
                                    'padding': '10px'}),
                    html.Div(dcc.Graph(id='top-ips'),
                             style={'width': '48%', 'display': 'inline-block',
                                    'padding': '10px'}),
                ]),
                dcc.Graph(id='port-activity'),
                dcc.Graph(id='packet-size'),
            ]),

            # Fires every 5 seconds and triggers all chart callbacks
            dcc.Interval(id='interval-component', interval=5_000, n_intervals=0)

        ], style={'fontFamily': 'Arial, sans-serif', 'backgroundColor': '#f4f6f7'})

    def _setup_callbacks(self):
        app = self.app

        def _get_data(n):
            if self.data_callback is not None:
                try:
                    return self.data_callback()
                except Exception as exc:
                    logger.error(f"data_callback raised: {exc}")
            return self.df, self.alerts

        @app.callback(Output('stats-row', 'children'),
                      Input('interval-component', 'n_intervals'))
        def update_stats(n):
            df, alerts = _get_data(n)
            total_packets = len(df)
            alert_count   = len(alerts)
            unique_ips    = df['source_ip'].nunique() if not df.empty else 0
            total_data    = df['size'].sum() / (1024 * 1024) if not df.empty else 0
            card_style = {
                'color': 'white', 'padding': '20px', 'margin': '10px',
                'borderRadius': '10px', 'textAlign': 'center', 'flex': '1'
            }
            return [
                _stat_card(f"{total_packets:,}", "Total Packets",    '#3498db', card_style),
                _stat_card(str(alert_count),     "Active Alerts",    '#e74c3c', card_style),
                _stat_card(str(unique_ips),       "Unique IPs",       '#2ecc71', card_style),
                _stat_card(f"{total_data:.2f} MB","Data Transferred", '#f39c12', card_style),
            ]

        @app.callback(Output('alerts-container', 'children'),
                      Input('interval-component', 'n_intervals'))
        def update_alerts(n):
            _, alerts = _get_data(n)
            return _render_alerts(alerts)

        @app.callback(Output('traffic-volume', 'figure'),
                      Input('interval-component', 'n_intervals'))
        def update_traffic(n):
            df, _ = _get_data(n)
            return _traffic_chart(df)

        @app.callback(Output('protocol-dist', 'figure'),
                      Input('interval-component', 'n_intervals'))
        def update_protocol(n):
            df, _ = _get_data(n)
            return _protocol_chart(df)

        @app.callback(Output('top-ips', 'figure'),
                      Input('interval-component', 'n_intervals'))
        def update_top_ips(n):
            df, _ = _get_data(n)
            return _top_ips_chart(df)

        @app.callback(Output('port-activity', 'figure'),
                      Input('interval-component', 'n_intervals'))
        def update_ports(n):
            df, _ = _get_data(n)
            return _port_activity_chart(df)

        @app.callback(Output('packet-size', 'figure'),
                      Input('interval-component', 'n_intervals'))
        def update_packet_size(n):
            df, _ = _get_data(n)
            return _packet_size_chart(df)

    def update_data(self, new_df, new_alerts):
        """Use this to push data manually when not using data_callback."""
        self.df     = new_df
        self.alerts = new_alerts

    def run(self, host='127.0.0.1', port=8050, debug=False):
        logger.info(f"Starting dashboard at http://{host}:{port}")
        self.app.run(host=host, port=port, debug=debug)


# --- Stateless helper functions ---

def _stat_card(value, label, color, base_style):
    style = {**base_style, 'backgroundColor': color}
    return html.Div([html.H3(value), html.P(label)], style=style)


def _render_alerts(alerts):
    if not alerts:
        return html.P("✅ No active alerts", style={'color': '#27ae60', 'fontSize': '18px'})
    severity_colors = {
        'CRITICAL': '#c0392b', 'HIGH': '#e74c3c',
        'MEDIUM':   '#f39c12', 'LOW':  '#3498db'
    }
    items = []
    for alert in alerts[:10]:
        color = severity_colors.get(alert.get('severity', 'LOW'), '#3498db')
        items.append(html.Div([
            html.Span(f"[{alert['severity']}]",
                      style={'color': color, 'fontWeight': 'bold', 'marginRight': '10px'}),
            html.Span(f"{alert['type']}: ", style={'fontWeight': 'bold'}),
            html.Span(alert['description'])
        ], style={'padding': '10px', 'borderBottom': '1px solid #ddd'}))
    return html.Div(items)


def _empty_fig(message="No data available"):
    return go.Figure().add_annotation(
        text=message, xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False
    )


def _traffic_chart(df):
    if df.empty or 'timestamp' not in df.columns:
        return _empty_fig()
    tmp = df.copy()
    tmp['timestamp'] = pd.to_datetime(tmp['timestamp'])
    series = tmp.set_index('timestamp').resample('10S').size()
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=series.index, y=series.values,
        mode='lines', name='Packets', fill='tozeroy',
        line=dict(color='#3498db', width=2)
    ))
    fig.update_layout(title='Network Traffic Volume Over Time',
                      xaxis_title='Time', yaxis_title='Packets / 10s',
                      hovermode='x unified', plot_bgcolor='white')
    return fig


def _protocol_chart(df):
    if df.empty or 'protocol_name' not in df.columns:
        return _empty_fig()
    counts = df['protocol_name'].value_counts()
    fig = go.Figure(data=[go.Pie(
        labels=counts.index, values=counts.values, hole=0.3,
        marker=dict(colors=['#3498db', '#e74c3c', '#2ecc71', '#f39c12'])
    )])
    fig.update_layout(title='Protocol Distribution')
    return fig


def _top_ips_chart(df):
    if df.empty or 'source_ip' not in df.columns:
        return _empty_fig()
    top = df['source_ip'].value_counts().head(10)
    fig = go.Figure(data=[go.Bar(
        x=top.values, y=top.index, orientation='h',
        marker=dict(color='#2ecc71')
    )])
    fig.update_layout(title='Top 10 Most Active Source IPs',
                      xaxis_title='Packet Count', yaxis_title='IP Address',
                      plot_bgcolor='white')
    return fig


def _port_activity_chart(df):
    if df.empty or 'dest_port' not in df.columns:
        return _empty_fig()
    counts = df['dest_port'].value_counts().head(15)
    fig = go.Figure(data=[go.Bar(
        x=counts.index, y=counts.values,
        marker=dict(color='#f39c12')
    )])
    fig.update_layout(title='Top 15 Destination Ports',
                      xaxis_title='Port', yaxis_title='Connections',
                      plot_bgcolor='white')
    return fig


def _packet_size_chart(df):
    if df.empty or 'size' not in df.columns:
        return _empty_fig()
    fig = go.Figure(data=[go.Histogram(
        x=df['size'], nbinsx=50,
        marker=dict(color='#9b59b6')
    )])
    fig.update_layout(title='Packet Size Distribution',
                      xaxis_title='Bytes', yaxis_title='Frequency',
                      plot_bgcolor='white')
    return fig


if __name__ == "__main__":
    sample_data = pd.DataFrame({
        'timestamp':      pd.date_range(start='2024-01-01', periods=1000, freq='1S'),
        'source_ip':      (['192.168.1.100', '192.168.1.101', '192.168.1.102'] * 334)[:1000],
        'destination_ip': ['8.8.8.8'] * 1000,
        'dest_port':      ([80, 443, 22] * 334)[:1000],
        'size':           ([1500, 800, 2000] * 334)[:1000],
        'protocol_name':  (['TCP', 'UDP', 'ICMP'] * 334)[:1000],
    })
    sample_alerts = [
        {'type': 'Port Scan', 'severity': 'HIGH',    'description': 'Multiple ports scanned from 192.168.1.100'},
        {'type': 'DDoS',      'severity': 'CRITICAL', 'description': 'High traffic volume detected'},
    ]
    dashboard = SecurityDashboard(sample_data, sample_alerts)
    print("Dashboard ready at http://127.0.0.1:8050")
    dashboard.run(debug=True)
