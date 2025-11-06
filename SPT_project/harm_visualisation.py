import plotly.graph_objects as go
import math


def visualize_upper_layer(harm_model):
    """
    upper layer visualization - Network topology
    """
    print("Creating upper layer visualization...")

    # Get hosts from HARM model
    hosts = list(harm_model[0].hosts())

    # Prepare data
    host_data = []
    for host in hosts:
        host_ip = host.name.decode('ascii') if isinstance(host.name, bytes) else str(host.name)

        # Count vulnerabilities
        vuln_count = len(list(host.lower_layer.all_vulns())) if hasattr(host, 'lower_layer') else 0

        # Classify host type and assign color
        if host_ip.startswith('10.0.2.'):
            tier = 'Web'
            color = 'red'
        elif host_ip.startswith('10.0.3.'):
            tier = 'App'
            color = 'yellow'
        elif host_ip.startswith('10.0.4.'):
            tier = 'DB'
            color = 'blue'
        else:
            tier = 'Unknown'
            color = 'gray'

        host_data.append({
            'ip': host_ip,
            'tier': tier,
            'color': color,
            'size': 30 + (vuln_count * 0.5)  # Base size 30, +2 per vulnerability
        })

    # Create layout positions
    positions = create_positions(host_data)

    # Create figure
    fig = go.Figure()

    # Add attacker node
    fig.add_trace(go.Scatter(
        x=[0],
        y=[0],
        mode='markers+text',
        marker=dict(size=40, color='black'),
        text=['Attacker'],
        textposition='bottom center',
        name='Attacker',
        showlegend=False
    ))

    # Add host nodes
    for i, host in enumerate(host_data):
        x, y = positions[i]

        fig.add_trace(go.Scatter(
            x=[x],
            y=[y],
            mode='markers+text',
            marker=dict(
                size=host['size'],
                color=host['color'],
                line=dict(width=2, color='white')
            ),
            text=[f"{host['ip']}<br>{host['tier']}"],
            textposition='bottom center',
            name=host['tier'],
            showlegend=False
        ))

    # Add connection lines
    add_connections(fig, positions, host_data)

    # Configure layout
    fig.update_layout(
        title=dict(text='HARM Upper Layer - Network Topology', x=0.5),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-2, 8]),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-1, 4]),
        plot_bgcolor='white',
        width=800,
        height=600
    )

    # Save file
    fig.write_html("harm_upper_layer.html")
    print("Upper layer saved: harm_upper_layer.html")


def create_positions(host_data):
    """
    Create tier-based positions for hosts
    """
    positions = []
    web_count = sum(1 for h in host_data if h['tier'] == 'Web')
    app_count = sum(1 for h in host_data if h['tier'] == 'App')
    db_count = sum(1 for h in host_data if h['tier'] == 'DB')

    web_x = 2
    app_x = 4
    db_x = 6

    web_index = 0
    app_index = 0
    db_index = 0

    for host in host_data:
        if host['tier'] == 'Web':
            x = web_x
            y = 1 + (web_index * 1.5) - (web_count * 0.75) + 0.75
            web_index += 1
        elif host['tier'] == 'App':
            x = app_x
            y = 1 + (app_index * 1.5) - (app_count * 0.75) + 0.75
            app_index += 1
        elif host['tier'] == 'DB':
            x = db_x
            y = 1 + (db_index * 1.5) - (db_count * 0.75) + 0.75
            db_index += 1
        else:
            x = 3
            y = 3

        positions.append((x, y))

    return positions


def add_connections(fig, positions, host_data):
    """
    Add connection lines between tiers
    """
    # Attacker to Web servers
    for i, host in enumerate(host_data):
        if host['tier'] == 'Web':
            x, y = positions[i]
            fig.add_trace(go.Scatter(
                x=[0, x],
                y=[0, y],
                mode='lines',
                line=dict(width=2, color='gray'),
                showlegend=False,
                hoverinfo='skip'
            ))

    # Web to App connections
    web_positions = [(positions[i], i) for i, host in enumerate(host_data) if host['tier'] == 'Web']
    app_positions = [(positions[i], i) for i, host in enumerate(host_data) if host['tier'] == 'App']

    for web_pos, _ in web_positions:
        for app_pos, _ in app_positions:
            fig.add_trace(go.Scatter(
                x=[web_pos[0], app_pos[0]],
                y=[web_pos[1], app_pos[1]],
                mode='lines',
                line=dict(width=2, color='gray'),
                showlegend=False,
                hoverinfo='skip'
            ))

    # App to DB connections
    db_positions = [(positions[i], i) for i, host in enumerate(host_data) if host['tier'] == 'DB']

    for app_pos, _ in app_positions:
        for db_pos, _ in db_positions:
            fig.add_trace(go.Scatter(
                x=[app_pos[0], db_pos[0]],
                y=[app_pos[1], db_pos[1]],
                mode='lines',
                line=dict(width=2, color='gray'),
                showlegend=False,
                hoverinfo='skip'
            ))
def visualize_lower_layer(harm_model):
    """
    Lower layer visualization
    """
    print("Creating lower layer visualization...")

    hosts = list(harm_model[0].hosts())
    num_hosts = len(hosts)
    fig = go.Figure()

    # framework at top center
    fw_x, fw_y = 0, 6
    fig.add_trace(go.Scatter(x=[fw_x], y=[fw_y], mode='markers+text',
                             marker=dict(size=40, color='purple'),
                             text=['HARM Framework'], textposition='bottom center', showlegend=False))

    # host positions horizontally spaced under framework
    width = 10
    xs = []
    for i in range(num_hosts):
        xs.append(-width/2 + i * (width/(num_hosts-1)) if num_hosts > 1 else 0)
    host_positions = [(xs[i], 3.5) for i in range(num_hosts)]

    # draw hosts and link to framework
    for i, host in enumerate(hosts):
        host_ip = host.name.decode('ascii') if isinstance(host.name, bytes) else str(host.name)
        x, y = host_positions[i]
        # host marker
        fig.add_trace(go.Scatter(x=[x], y=[y], mode='markers+text',
                                 marker=dict(size=30, color='lightblue'),
                                 text=[host_ip], textposition='bottom center', showlegend=False))
        # line from framework to host
        fig.add_trace(go.Scatter(x=[fw_x, x], y=[fw_y, y], mode='lines',
                                 line=dict(width=2, color='black'), showlegend=False, hoverinfo='skip'))

    # for each host, print vulnerabilities as vertical text list below the host
    for i, host in enumerate(hosts):
        x, y = host_positions[i]
        host_ip = host.name.decode('ascii') if isinstance(host.name, bytes) else str(host.name)
        vulns = list(host.lower_layer.all_vulns()) if getattr(host, 'lower_layer', None) else []

        # show upto N entries; spread them vertically
        gap = 0.6
        start_y = y - 1.2
        for j, vuln in enumerate(vulns):
            vy = start_y - j * gap
            # label: ID - name - CVSS
            cve = vuln.name if hasattr(vuln, 'name') else (vuln.id if hasattr(vuln, 'id') else str(vuln))
            # some vulnerability objects have different attributes; try both
            v_name = vuln.values.get('vuln_name') if vuln.values and vuln.values.get('vuln_name') else ''
            cvss = vuln.values.get('risk') if vuln.values else ''
            label = f"{cve} {('- ' + str(v_name)) if v_name else ''} (CVSS:{cvss})"

            # add text node (no marker)
            fig.add_trace(go.Scatter(x=[x], y=[vy], mode='text',
                                     text=[label], textposition='middle center',
                                     textfont=dict(size=11), showlegend=False, hoverinfo='text'))

            # add line host -> vuln text
            fig.add_trace(go.Scatter(x=[x, x], y=[y - 0.25, vy + 0.06], mode='lines',
                                     line=dict(width=1, color='gray'), showlegend=False, hoverinfo='skip'))

    fig.update_layout(
        title=dict(text='HARM Lower Layer', x=0.5),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-6, 6]),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-3, 8]),
        plot_bgcolor='white', width=1200, height=900
    )

    fig.write_html("harm_lower_layer.html")
    print("Lower layer saved: harm_lower_layer.html")

def create_harm_visualizations(harm_model):
    """
    Main function to create both visualizations
    """
    print("=== Creating HARM Visualizations ===")

    # Create upper layer
    visualize_upper_layer(harm_model)

    # Create lower layer
    visualize_lower_layer(harm_model)


if __name__ == "__main__":
    # Import your HARM model
    from harm_construction import amazon_network_sim

    harm_model = amazon_network_sim()
    #create HARM visualisation
    create_harm_visualizations(harm_model)


