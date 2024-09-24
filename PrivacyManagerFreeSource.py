import sys
import psutil
import pygetwindow as gw
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QPushButton,
    QComboBox, QMessageBox, QLineEdit, QHBoxLayout, QTabWidget,
    QTableWidget, QTableWidgetItem, QHeaderView, QScrollBar
)
from PyQt5.QtCore import Qt
import os
import winreg  # Importing winreg to access the Windows registry

class PrivacyApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Privacy Manager")
        self.setGeometry(100, 100, 800, 600)
        self.setStyleSheet("background-color: #2E2E2E; color: #FFFFFF; font-family: Arial;")
        self.hidden_windows = []
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet(self.tab_styles())
        
        # Create tabs
        self.details_tab = self.create_details_tab()
        self.application_tab = self.create_application_tab()
        self.process_tab = self.create_process_tab()
        self.network_tab = self.create_network_tab()
        self.startup_tab = self.create_startup_tab()

        self.tabs.addTab(self.details_tab, "Details")
        self.tabs.addTab(self.application_tab, "Application Management")
        self.tabs.addTab(self.process_tab, "Running Processes")
        self.tabs.addTab(self.network_tab, "Network Monitor")
        self.tabs.addTab(self.startup_tab, "Startup Manager")
        self.tabs.setCurrentWidget(self.details_tab)  # Set default tab

        layout.addWidget(self.tabs)
        self.setLayout(layout)

    def tab_styles(self):
        return """
            QTabWidget::pane { border: 0; }
            QTabBar::tab { background: #444444; color: #FFFFFF; padding: 10px; }
            QTabBar::tab:selected { background: #555555; color: #FFFFFF; }
        """

    def create_details_tab(self):
        layout = QVBoxLayout()
        layout.addWidget(QLabel("How to Use the Privacy Manager").setStyleSheet("font-size: 20px; font-weight: bold;"))
        instructions = (
            "1. **Application Management**: Use this tab to manage running applications.\n"
            "   - You can hide, suspend, resume, restart, or close applications.\n"
            "2. **Running Processes**: View all currently running processes on your system.\n"
            "   - You can kill any process directly from this tab.\n"
            "3. **Network Monitor**: Monitor active network connections.\n"
            "   - View local and remote addresses, status, and protocol.\n"
            "4. **Startup Manager**: Manage applications that start with your OS.\n"
            "   - Enable or disable startup applications as needed.\n"
            "5. **Tips**: Regularly check for unwanted applications and processes to maintain privacy."
        )
        layout.addWidget(QLabel(instructions))
        tab = QWidget()
        tab.setLayout(layout)
        return tab

    def create_application_tab(self):
        layout = QVBoxLayout()
        self.search_input = QLineEdit(placeholderText="Search applications...")
        self.app_dropdown = QComboBox()
        self.populate_dropdown()
        layout.addWidget(self.search_input)
        layout.addWidget(self.app_dropdown)
        layout.addLayout(self.create_button_layout())
        tab = QWidget()
        tab.setLayout(layout)
        return tab

    def create_process_tab(self):
        layout = QVBoxLayout()
        self.process_table = self.create_table(["PID", "Name", "Status", "Memory Usage (MB)", "Action"])
        self.load_processes()
        layout.addWidget(self.process_table)
        layout.addWidget(QPushButton("Refresh Processes", clicked=self.load_processes))
        tab = QWidget()
        tab.setLayout(layout)
        return tab

    def create_network_tab(self):
        layout = QVBoxLayout()
        self.network_table = self.create_table(["Local Address", "Remote Address", "Status", "Protocol"])
        self.load_network_connections()
        layout.addWidget(self.network_table)
        tab = QWidget()
        tab.setLayout(layout)
        return tab

    def create_startup_tab(self):
        layout = QVBoxLayout()
        self.startup_table = self.create_table(["Name", "Path", "Enabled"])
        self.load_startup_items()
        layout.addWidget(self.startup_table)
        tab = QWidget()
        tab.setLayout(layout)
        return tab

    def create_table(self, headers):
        table = QTableWidget()
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        # Set no background color for table cells
        table.setStyleSheet("QTableWidget { background-color: transparent; color: #FFFFFF; }"
                            "QHeaderView::section { background-color: #444444; }")
        return table

    def create_button_layout(self):
        button_layout = QHBoxLayout()
        actions = [("Hide Application", self.hide_application), ("Show Hidden Applications", self.show_hidden_applications),
                   ("Clear Search", self.clear_search), ("Suspend Application", self.suspend_application),
                   ("Resume Application", self.resume_application), ("Restart Application", self.restart_application),
                   ("Close Application", self.close_application)]
        for label, action in actions:
            button = QPushButton(label)
            button.clicked.connect(action)
            button_layout.addWidget(button)
        return button_layout

    def populate_dropdown(self):
        self.app_dropdown.clear()
        open_windows = gw.getAllTitles()
        for title in open_windows:
            if title:
                self.app_dropdown.addItem(title)

    def load_processes(self):
        self.process_table.setRowCount(0)
        for proc in psutil.process_iter(attrs=['pid', 'name', 'status', 'memory_info']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']
                status = proc.info['status']
                mem_usage = proc.info['memory_info'].rss / (1024 * 1024)
                self.add_process_to_table(pid, name, status, mem_usage)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def add_process_to_table(self, pid, name, status, mem_usage):
        row_position = self.process_table.rowCount()
        self.process_table.insertRow(row_position)
        self.process_table.setItem(row_position, 0, QTableWidgetItem(str(pid)))
        self.process_table.setItem(row_position, 1, QTableWidgetItem(name))
        self.process_table.setItem(row_position, 2, QTableWidgetItem(status))
        self.process_table.setItem(row_position, 3, QTableWidgetItem(f"{mem_usage:.2f}"))
        kill_button = QPushButton("Kill")
        kill_button.clicked.connect(lambda: self.kill_process(pid))
        self.process_table.setCellWidget(row_position, 4, kill_button)

    def load_network_connections(self):
        self.network_table.setRowCount(0)
        for conn in psutil.net_connections(kind='inet'):
            local_address = f"{conn.laddr[0]}:{conn.laddr[1]}"
            remote_address = f"{conn.raddr[0]}:{conn.raddr[1]}" if conn.raddr else "N/A"
            self.add_network_to_table(local_address, remote_address, conn.status, conn.type)

    def add_network_to_table(self, local_address, remote_address, status, protocol):
        row_position = self.network_table.rowCount()
        self.network_table.insertRow(row_position)
        self.network_table.setItem(row_position, 0, QTableWidgetItem(local_address))
        self.network_table.setItem(row_position, 1, QTableWidgetItem(remote_address))
        self.network_table.setItem(row_position, 2, QTableWidgetItem(status))
        self.network_table.setItem(row_position, 3, QTableWidgetItem(str(protocol)))

    def load_startup_items(self):
        self.startup_table.setRowCount(0)
        # Load startup items from the registry
        registry_paths = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
        ]
        for path in registry_paths:
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
                    for i in range(0, winreg.QueryInfoKey(key)[1]):
                        name, value, _ = winreg.EnumValue(key, i)
                        self.add_startup_to_table(name, value)
            except WindowsError:
                continue

    def add_startup_to_table(self, name, path):
        row_position = self.startup_table.rowCount()
        self.startup_table.insertRow(row_position)
        self.startup_table.setItem(row_position, 0, QTableWidgetItem(name))
        self.startup_table.setItem(row_position, 1, QTableWidgetItem(path))
        enabled_item = QTableWidgetItem("Enabled")
        self.startup_table.setItem(row_position, 2, enabled_item)
        # Add a button to disable the startup item
        disable_button = QPushButton("Disable")
        disable_button.clicked.connect(lambda: self.disable_startup_item(name))
        self.startup_table.setCellWidget(row_position, 3, disable_button)

    def disable_startup_item(self, name):
        registry_paths = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
        ]
        for path in registry_paths:
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.DeleteValue(key, name)
                    QMessageBox.information(self, "Success", f"{name} has been disabled from startup.")
                    self.load_startup_items()  # Refresh the startup items
                    return
            except WindowsError:
                continue
        QMessageBox.warning(self, "Error", f"{name} could not be found in startup items.")

    def hide_application(self):
        selected_title = self.app_dropdown.currentText()
        if selected_title:
            windows = gw.getWindowsWithTitle(selected_title)
            for window in windows:
                window.hide()
                self.hidden_windows.append(window)
            QMessageBox.information(self, "Success", f"{selected_title} has been hidden.")

    def show_hidden_applications(self):
        for window in self.hidden_windows:
            window.show()
        self.hidden_windows.clear()
        QMessageBox.information(self, "Success", "All hidden applications have been shown.")

    def clear_search(self):
        self.search_input.clear()
        self.populate_dropdown()

    def suspend_application(self):
        self.change_application_state("suspend")

    def resume_application(self):
        self.change_application_state("resume")

    def change_application_state(self, action):
        selected_title = self.app_dropdown.currentText()
        if selected_title:
            pid = self.get_pid_from_title(selected_title)
            if pid:
                process = psutil.Process(pid)
                getattr(process, action)()
                QMessageBox.information(self, "Success", f"{selected_title} has been {action}ed.")

    def restart_application(self):
        selected_title = self.app_dropdown.currentText()
        if selected_title:
            pid = self.get_pid_from_title(selected_title)
            if pid:
                process = psutil.Process(pid)
                process.terminate()
                # Restart logic omitted for brevity

    def close_application(self):
        selected_title = self.app_dropdown.currentText()
        if selected_title:
            windows = gw.getWindowsWithTitle(selected_title)
            for window in windows:
                window.close()
            QMessageBox.information(self, "Success", f"{selected_title} has been closed.")

    def get_pid_from_title(self, title):
        for proc in psutil.process_iter(attrs=['pid', 'name']):
            if title.lower() in proc.info['name'].lower():
                return proc.info['pid']
        return None

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = PrivacyApp()
    window.show()
    sys.exit(app.exec_())