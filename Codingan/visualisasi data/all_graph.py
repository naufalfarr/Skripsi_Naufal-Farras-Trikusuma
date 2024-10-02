import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import mplcursors

# Load data from CSV file
df = pd.read_csv('sensor_data_aes.csv', parse_dates=['Timestamp'])

# Convert the Timestamp column to datetime
df['Timestamp'] = pd.to_datetime(df['Timestamp'])

# Create a time column in seconds since the start of the data
df['Time (s)'] = (df['Timestamp'] - df['Timestamp'].iloc[0]).dt.total_seconds()

# Set up the figure with 3 subplots (1 row, 3 columns)
fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(15, 12))

# Plot Power (mW) with dot markers on the first subplot (ax1)
line1, = ax1.plot(df['Time (s)'], df['Power (mW)'], label='Power (mW)', marker='o', linestyle='-', color='tab:blue')
ax1.set_xlabel('Time (s)')
ax1.set_ylabel('Power (mW)', color='tab:blue')
ax1.tick_params(axis='y', labelcolor='tab:blue')
ax1.grid(True)
ax1.set_title('Power Over Time')
ax1.xaxis.set_major_locator(ticker.MultipleLocator(0.5))  # Set the tick every 0.5 seconds (500 ms)

# Plot Load Voltage (V) on the second subplot (ax2)
line2, = ax2.plot(df['Time (s)'], df['Load Voltage (V)'], label='Load Voltage (V)', linestyle='-', color='tab:red')
ax2.set_xlabel('Time (s)')
ax2.set_ylabel('Load Voltage (V)', color='tab:red')
ax2.tick_params(axis='y', labelcolor='tab:red')
ax2.grid(True)
ax2.set_title('Load Voltage Over Time')
ax2.xaxis.set_major_locator(ticker.MultipleLocator(0.5))  # Set the tick every 0.5 seconds (500 ms)

# Plot Current (mA) on the third subplot (ax3)
line3, = ax3.plot(df['Time (s)'], df['Current (mA)'], label='Current (mA)', linestyle='-', color='tab:green')
ax3.set_xlabel('Time (s)')
ax3.set_ylabel('Current (mA)', color='tab:orange')
ax3.tick_params(axis='y', labelcolor='tab:orange')
ax3.grid(True)
ax3.set_title('Current Over Time')
ax3.xaxis.set_major_locator(ticker.MultipleLocator(0.5))  # Set the tick every 0.5 seconds (500 ms)

# Enable interactive cursor for hover functionality on all three plots
mplcursors.cursor([line1, line2, line3], hover=True)

# Adjust layout to prevent overlap
plt.tight_layout()

# Show the plot
plt.show()
