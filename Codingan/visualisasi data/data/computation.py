import matplotlib.pyplot as plt

# Data
algorithms = ['ChaCha20', 'AES256', 'Snow-V', 'CLEFIA256']
average_times = [79.3, 400.8, 176, 345.4]

# Create the bar chart
plt.figure(figsize=(10, 6))
plt.bar(algorithms, average_times, color=['#4CAF50', '#2196F3', '#FFC107', '#FF5722'])

# Add labels and title
plt.xlabel('Encryption Algorithms')
plt.ylabel('Average Computation Time in Microsecond (μs)')
plt.title('Average Computation Time for Different Encryption Algorithms')
plt.ylim(0, 450)

# Show the values on top of the bars
for i, time in enumerate(average_times):
    plt.text(i, time + 10, f"{time} μs", ha='center')

# Display the plot
plt.show()
