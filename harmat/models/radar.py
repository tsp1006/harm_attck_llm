import numpy as np
import matplotlib.pyplot as plt

# Define the data
labels = np.array(['P-CSCF', 'S-CSCF', 'SGW', 'SIP-AS', 'MRFC'])
before_values = np.array([1.61, 6.80, 5.29, 2.69, 6.75])
after_values = np.array([0.0, 3.70, 3.30, 1.54, 5.69])

# Number of variables
num_vars = len(labels)

# Compute angle for each axis
angles = np.linspace(0, 2 * np.pi, num_vars, endpoint=False).tolist()

# The plot is a closed circle, so we need to "complete the loop"
before_values = np.concatenate((before_values, [before_values[0]]))
after_values = np.concatenate((after_values, [after_values[0]]))
angles += angles[:1]

# Create the radar chart
fig, ax = plt.subplots(figsize=(7, 7), subplot_kw=dict(polar=True))

# Draw one axe per variable and add labels with black color and increased size
plt.xticks(angles[:-1], labels, color='black', size=20)

# Draw ylabels
ax.set_ylim(0, 7)

# Increase font size and make y-axis labels bold
ax.tick_params(labelsize=25)

# Plot the "before" values
ax.plot(angles, before_values, color='red', linewidth=2, linestyle='solid', label='Before patch')

# Fill the area under the "before" values
ax.fill(angles, before_values, color='red', alpha=0.25)

# Mark points for "before" values
for i in range(num_vars):
    ax.plot(angles[i], before_values[i], 'o', color='red', markersize=8)

# Plot the "after" values
ax.plot(angles, after_values, color='blue', linewidth=2, linestyle='solid', label='After patch')

# Fill the area under the "after" values
ax.fill(angles, after_values, color='blue', alpha=0.25)

# Mark points for "after" values
for i in range(num_vars):
    ax.plot(angles[i], after_values[i], 'o', color='blue', markersize=8)

# Add a title for the radar chart
#plt.title('Before and After Vulnerability Patch Based on Critical Threats', size=20, color='black', weight='bold')

# Add a legend with a title and increased font size
plt.legend(loc='upper right', bbox_to_anchor=(0.1, 0.1), fontsize=25, title='Threat-specific risk', title_fontsize='25')

# Show the radar chart
plt.show()
