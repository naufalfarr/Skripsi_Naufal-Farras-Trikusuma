import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import mplcursors

# Load data from CSV file
df = pd.read_csv('sensor_data_chacha_v2.csv', parse_dates=['Timestamp'])

# Convert the Timestamp column to datetime
df['Timestamp'] = pd.to_datetime(df['Timestamp'])

# Create a time column in seconds since the start of the data
df['Time (s)'] = (df['Timestamp'] - df['Timestamp'].iloc[0]).dt.total_seconds()

# Convert Power from mW to W
df['Power (W)'] = df['Power (mW)'] / 1000

# Calculate the time differences (dt) between consecutive data points
df['Time Difference (s)'] = df['Time (s)'].diff().fillna(0)

# Calculate the incremental energy (in joules) for each time interval
df['Energy (J)'] = df['Power (W)'] * df['Time Difference (s)']

# Calculate the cumulative energy over time
df['Cumulative Energy (J)'] = df['Energy (J)'].cumsum()

# Set up the figure
plt.figure(figsize=(15, 6))

# Plotting Cumulative Energy with dot markers
line, = plt.plot(df['Time (s)'], df['Cumulative Energy (J)'], label='Cumulative Energy (J)', marker='o', linestyle='-')

# Formatting the plot
plt.title('Cumulative Energy Over Time')
plt.xlabel('Time (s)')
plt.ylabel('Cumulative Energy (J)')
plt.legend()
plt.grid(True)

# Set x-axis ticks to be every 500 ms
plt.gca().xaxis.set_major_locator(ticker.MultipleLocator(0.5))  # Set the tick every 0.5 seconds (500 ms)

# Enable interactive cursor for hover functionality
mplcursors.cursor(line, hover=True)

# Show the plot
plt.tight_layout()
plt.show()
