import pandas as pd
import matplotlib
matplotlib.use('Agg')  
import matplotlib.pyplot as plt
import seaborn as sns
from io import BytesIO
import base64
import os

base_dir = os.path.dirname(os.path.abspath(__file__))
file_path = os.path.join(base_dir, "Final_Dataset.csv")


df = pd.read_csv(file_path)


def plot_to_base64():
    fig = plt.gcf()  
    buf = BytesIO()
    fig.savefig(buf, format='png', bbox_inches='tight')
    plt.close(fig)  
    buf.seek(0)
    return base64.b64encode(buf.read()).decode('utf-8')


def plot_aqi_histogram(month):
    df_filtered = df[df["month"] == month]
    aqi_trend = df_filtered.groupby("year")["AQI"].mean()

    plt.figure(figsize=(10, 7))
    plt.bar(aqi_trend.index, aqi_trend.values, color='b', edgecolor="black")
    plt.xlabel("Year")
    plt.ylabel("Average AQI")
    plt.title(f"Average AQI for Month {month} Across All Years")
    plt.xticks(aqi_trend.index, rotation=45)

    return plot_to_base64()

def plot_pollutant_contribution(month):
    df_filtered = df[df["month"] == month]
    pollutant_columns = [col for col in df.columns if col not in ["year", "month", "AQI"]]
    df_filtered.loc[:, pollutant_columns] = df_filtered[pollutant_columns].apply(pd.to_numeric, errors='coerce')

    pollutant_sums = df_filtered[pollutant_columns].sum()
    pollutant_sums = pollutant_sums[pollutant_sums > 0]

    if pollutant_sums.empty:
        return None  

    plt.figure(figsize=(8, 8))
    plt.pie(pollutant_sums, labels=pollutant_sums.index, autopct="%1.1f%%",
            startangle=140, colors=plt.cm.Paired.colors)
    plt.title(f"Pollutant Contribution to AQI for Month {month} Across All Years")

    return plot_to_base64()

def plot_aqi_trend(month):
    df_filtered = df[df["month"] == month]
    aqi_trend = df_filtered.groupby("year")["AQI"].mean()

    plt.figure(figsize=(10, 5))
    plt.plot(aqi_trend.index, aqi_trend.values, marker="o", linestyle="-", color="b",
             label=f"Average AQI for Month {month}")
    plt.xlabel("Year")
    plt.ylabel(f"Average AQI in Month {month}")
    plt.title(f"AQI Trend for Month {month} Across All Years")
    plt.xticks(aqi_trend.index)
    plt.grid(True, linestyle="--", alpha=0.6)
    plt.legend()

    return plot_to_base64()

def plot_aqi_heatmap(month):
    df_filtered = df[df["month"] == month]
    heatmap_data = df_filtered.pivot_table(values="AQI", index="year", aggfunc="mean")

    plt.figure(figsize=(8, 6))
    sns.heatmap(heatmap_data, cmap="coolwarm", annot=True, fmt=".1f", linewidths=0.5)
    plt.title(f"AQI Heatmap for Month {month} Across All Years")
    plt.xlabel("Year")
    plt.ylabel("")

    return plot_to_base64()
