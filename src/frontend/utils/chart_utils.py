from PyQt5.QtWidgets import QSizePolicy
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from src.config.constants import SEVERITY_COLORS_CHART



class VulnerabilityPieChart(FigureCanvas):
    """Matplotlib-based pie chart for vulnerability severity visualization."""
    def __init__(self, parent=None, width=5, height=5, dpi=100):
        self.fig = Figure(figsize=(width, height), dpi=dpi)
        self.axes = self.fig.add_subplot(111)
        super(VulnerabilityPieChart, self).__init__(self.fig)
        self.setParent(parent)

        # Make the background match the application theme
        self.fig.patch.set_facecolor('#1e1e1e')
        self.axes.set_facecolor('#1e1e1e')

        # Set text color to white for better visibility
        self.axes.tick_params(colors='white')
        for text in self.axes.texts:
            text.set_color('white')

        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

    def update_chart(self, severity_data):
        """Update the pie chart with new severity data."""
        self.axes.clear()

        labels = []
        sizes = []

        # Define the order we want
        severity_order = ["Critical", "High", "Medium", "Low", "None"]

        # Sort data by predefined order
        for severity in severity_order:
            if severity in severity_data and severity_data[severity] > 0:
                labels.append(f"{severity} ({severity_data[severity]})")
                sizes.append(severity_data[severity])

        colors = SEVERITY_COLORS_CHART

        color_list = [colors[severity] for severity in severity_order if
                      severity in severity_data and severity_data[severity] > 0]
        explode = [0.1 if l.startswith("Critical") else 0 for l in labels]

        if sizes:  # Only create pie if we have data
            self.axes.pie(
                sizes,
                labels=labels,
                autopct='%1.1f%%',
                colors=color_list,
                explode=explode,
                startangle=140,
                textprops={'color': 'white'}
            )
            self.axes.set_title("Distribution of CVE Severities", color='white')
            self.axes.axis("equal")

        self.fig.tight_layout()
        self.draw()