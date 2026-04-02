import pandas as pd 
import plotly.express as px
from dash import Dash, html, dcc, Input, Output
from scripts.analyze_logs import detect_suspicious_ips, parse_all_logs


#Initalizing app
app = Dash(__name__) 

#server = app.server
server = app.server

#read the text file ad store it in a dataframe
with open('data/ssh_logs.txt', 'r') as file:
    logs = file.readlines()

df = parse_all_logs(logs)

suspicious_ips, ip_counts, top_attacker = detect_suspicious_ips(df)

#===== BAR CHART =====
bar_chart = px.bar(
    ip_counts, x='ip', y='count',
    title='Number of Login Attempts per IP Address',
    labels={'IP Address': 'IP Address', 'Number of Attempts': 'Number of Attempts'},
    color='count',
    color_continuous_scale='Viridis'
)

#============ DASHBOARD LAYOUT ==============
app.layout = html.Div(style={"backgroundColor": "#161617", "fontFamily": "Times New Roman","margin": "0", "padding": "0", "minHeight": "100vh"}, children=[
    #Title - Heading
    html.H1("SSH Log Analysis Dashboard", 
        style={"color": "#D3D5E1", "textAlign": "center", "marginBottom": "0px"}),
    html.P("Dashboard for analyzing SSH login attempts and tracking suspicious activity on a live moinitor",
        style={"color": "#ffffff", "textAlign": "center", "fontStyle": "italic", "marginBottom": "30px"}),
  

#============CARD 1 ==============
    html.Div(style={"display": "flex", "justifyContent": "space-between", "padding": "20px"}, children=[
        html.Div(style = {"backgroundColor": "#06067A", "padding": "20px", "borderRadius": "10px",
                         "textAlign": "center", "width": "20%", "border": "1px solid #00d4ff"}, children = [
            html.H3("Total attacks detected", style = {"color": "#aaaaaa", "fontSize": "14px"}),
            html.H2(f"{len(suspicious_ips)}", style = {"color": "#ffffff", "fontSize": "24px", "marginTop": "10px"}),
        ]),
    
    #============CARD 2 ==============
        html.Div(style = {"backgroundColor": "#06067A", "padding": "20px", "borderRadius": "10px",
                          "textAlign": "center", "width": "20%", "border": "1px solid #00d4ff"}, children = [
            html.H3("Suspicious IPs Count", style = {"color": "#aaaaaa", "fontSize": "14px"}),
            html.H2(f"{suspicious_ips['count'].sum()}", style = {"color": "#ffffff", "fontSize": "24px", "marginTop": "10px"}),   
        ]),
                         
    #============CARD 3 ==============
        html.Div(style = {"backgroundColor": "#06067A", "padding": "20px", "borderRadius":"10px",
                          "textAlign": "center", "width": "20%", "border": "1px solid #00d4ff"}, children = [
            html.H3("Most Active Attacker", style = {"color": "#aaaaaa", "fontSize": "14px"}),
            html.H2(f"{top_attacker}",
                    style = {"color": "#ffffff", "fontSize": "24px", "marginTop": "10px"}),
        ]),

    #============CARD 4 ==============
        html.Div(style = {"backgroundColor": "#06067A", "padding": "20px", "borderRadius": "10px",
                          "textAlign": "center", "width": "20%", "border": "1px solid #00d4ff"}, children = [
            html.H3("Last attack timestamp", style = {"color": "#aaaaaa", "fontSize": "14px"}),
            html.H2(f"{df['timestamp'].iloc[-1]}",
                    style = {"color": "#ffffff", "fontSize": "24px", "marginTop": "10px"}),
    ]),
]),

#============Chart 1 ===========
html.H2("Login Attempts by IP Address",
        style={"color": "#ffffff", "textAlign": "center"}),
    

    #====refresh data  for live monitor 
    dcc.Interval(
        id = 'interval-update',
        interval = 5000, # 5 seconds in milliseconds
        n_intervals = 0 # number of times the interval has passed
    ),
    dcc.Graph(
        id = "bar-chart",
        style={"backgroundColor": "#161617"}
        )#id to use to callback 

])

#============= Chart 2 ==============



#============CALLBACK bar-chart ==============

@app.callback(
    Output('bar-chart', 'figure'),
    Input('interval-update', 'n_intervals')
)
def refesh_chart(n):
    with open('data/ssh_logs.txt', 'r') as file:
        logs = file.readlines()
    df = parse_all_logs(logs)
    suspicious_ips, ip_counts, top_attacker = detect_suspicious_ips(df)
    fig = px.bar(
        ip_counts, x='ip', y='count',
        title='Number of Login Attempts per IP Address',
        labels={'IP Address': 'IP Address', 'Number of Attempts': 'Number of Attempts'},
        color='count',
        color_continuous_scale='Viridis'
    )
    return fig
    
#Run the app
if __name__ == "__main__":
    app.run(
        debug=True,
        host="0.0.0.0",
        port=8050
    )