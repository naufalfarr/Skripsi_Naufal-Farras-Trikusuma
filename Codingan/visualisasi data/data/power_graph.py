import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import mplcursors

# Load data from CSV file
df = pd.read_csv('sensor_data_clefia256.csv', parse_dates=['Timestamp'])

# Convert the Timestamp column to datetime
df['Timestamp'] = pd.to_datetime(df['Timestamp'])

# Create a time column in seconds since the start of the data
df['Time (s)'] = (df['Timestamp'] - df['Timestamp'].iloc[0]).dt.total_seconds()

# Set up the figure
plt.figure(figsize=(15, 6))

# Plotting Power with dot markers
line, = plt.plot(df['Time (s)'], df['Power (mW)'], label='Power (mW)', marker='o', linestyle='-')

# Formatting the plot
plt.title('Power Over Time Clefia256')
plt.xlabel('Time (s)')
plt.ylabel('Power (mW)')
plt.legend()
plt.grid(True)

# Set x-axis ticks to be every 500 ms
plt.gca().xaxis.set_major_locator(ticker.MultipleLocator(0.5))  # Set the tick every 0.5 seconds (500 ms)

# Enable interactive cursor for hover functionality
mplcursors.cursor(line, hover=True)

# Show the plot
plt.tight_layout()
plt.show()