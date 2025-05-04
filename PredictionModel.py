import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler, OneHotEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import classification_report
import joblib
from rich.console import Console
from rich.progress import Progress
import warnings
import socket
import json

HOST = "0.0.0.0"
PORT = 5000

warnings.filterwarnings('ignore')

console = Console()

def preprocess(dataframe, is_train=True):
    console.log("Preprocessing data...")
    cat_cols = ['protocol_type', 'service', 'flag']
    num_cols = [col for col in dataframe.columns if col not in cat_cols + ['outcome', 'level']]

    if is_train:
        console.log("Encoding categorical columns...")
        encoder = OneHotEncoder(handle_unknown='ignore', sparse_output=False)
        encoded = pd.DataFrame(encoder.fit_transform(dataframe[cat_cols]))
        encoded.columns = encoder.get_feature_names_out(cat_cols)
        dataframe = dataframe.drop(cat_cols, axis=1).reset_index(drop=True)
        dataframe = pd.concat([dataframe, encoded], axis=1)
        joblib.dump(encoder, "encoder.pkl")
    else:
        console.log("Loading encoder for categorical columns...")
        encoder = joblib.load("encoder.pkl")
        encoded = pd.DataFrame(encoder.transform(dataframe[cat_cols]))
        encoded.columns = encoder.get_feature_names_out(cat_cols)
        dataframe = dataframe.drop(cat_cols, axis=1).reset_index(drop=True)
        dataframe = pd.concat([dataframe, encoded], axis=1)

    if is_train:
        console.log("Scaling numerical columns...")
        scaler = RobustScaler()
        dataframe[num_cols] = scaler.fit_transform(dataframe[num_cols])
        joblib.dump(scaler, "scaler.pkl")
    else:
        console.log("Loading scaler for numerical columns...")
        scaler = joblib.load("scaler.pkl")
        dataframe[num_cols] = scaler.transform(dataframe[num_cols])

    return dataframe

def train_and_save_model(data_path):
    console.log("Loading data from file...")
    columns = [
        'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land',
        'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
        'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
        'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
        'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
        'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
        'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
        'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
        'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
        'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'outcome', 'level'
    ]

    data = pd.read_csv(data_path, names=columns)
    console.log("Converting outcome column to binary labels...")
    data['outcome'] = data['outcome'].apply(lambda x: 0 if x == 'normal' else 1)

    data = preprocess(data)

    console.log("Splitting data into features and target...")
    X = data.drop(['outcome', 'level'], axis=1).values
    y = data['outcome'].values

    console.log("Splitting data into training and test sets...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    with Progress() as progress:
        train_task = progress.add_task("[green]Training models...", total=100)

        console.log("Training Random Forest model...")
        rf_model = RandomForestClassifier(
            n_estimators=50,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2,
            max_features='sqrt',
            bootstrap=True,
            random_state=42
        )
        rf_model.fit(X_train, y_train)
        joblib.dump(rf_model, "rf_model.pkl")
        progress.update(train_task, advance=50)

        console.log("Training Decision Tree model...")
        dt_model = DecisionTreeClassifier(max_depth=5)
        dt_model.fit(X_train, y_train)
        joblib.dump(dt_model, "dt_model.pkl")
        progress.update(train_task, advance=50)

    console.log("Evaluating models...")
    rf_predictions = rf_model.predict(X_test)
    dt_predictions = dt_model.predict(X_test)
    console.log("[bold yellow]Random Forest Classification Report:[/bold yellow]\n" + classification_report(y_test, rf_predictions))
    console.log("[bold yellow]Decision Tree Classification Report:[/bold yellow]\n" + classification_report(y_test, dt_predictions))

    console.log("[green]Models saved successfully![/green]")

def predict(input_data):
    console.log("Loading models and preprocessors for prediction...")
    scaler = joblib.load("scaler.pkl")
    encoder = joblib.load("encoder.pkl")
    rf_model = joblib.load("rf_model.pkl")
    dt_model = joblib.load("dt_model.pkl")

    console.log("Preprocessing input data...")
    input_data = preprocess(input_data, is_train=False)

    console.log("Making predictions...")
    rf_prediction = rf_model.predict(input_data)
    dt_prediction = dt_model.predict(input_data)

    return {"Random Forest": rf_prediction, "Decision Tree": dt_prediction}

def handle_live_data():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)

    print(f"Server listening on {HOST}:{PORT}")
    conn, addr = server.accept()
    print(f"Connection from {addr}")

    with conn:
        while True:
            data = conn.recv(4096)
            if not data:
                break

            try:
                input_data = json.loads(data.decode())  
                input_df = pd.DataFrame([input_data])
                test_data = preprocess(input_df, is_train=False)

                rf_prediction = rf_model.predict(test_data)[0]
                rf_proba = rf_model.predict_proba(test_data)[0]
                dt_prediction = dt_model.predict(test_data)[0]
                dt_proba = dt_model.predict_proba(test_data)[0]
         
                rf_confidence = rf_proba[1] if rf_prediction == 1 else rf_proba[0]
                dt_confidence = dt_proba[1] if dt_prediction == 1 else dt_proba[0]

                rf_threshold = 0.5
                dt_threshold = 0.5
                
                rf_label = "✅ Normal traffic" if rf_prediction == 0 and rf_confidence >= rf_threshold else "[red]🚨 ALERT: Attack detected![/red]"
                dt_label = "✅ Normal traffic" if dt_prediction == 0 and dt_confidence >= dt_threshold else "[red]🚨 ALERT: Attack detected![/red]"

                if rf_label == "[red]🚨 ALERT: Attack detected![/red]" and dt_label == "[red]🚨 ALERT: Attack detected![/red]": 
                    conn.sendall(json.dumps({"status": "problematic_packet", "data": input_data}).encode() + b"\n")
                    console.log("[yellow]Problematic packet sent back to the client for analysis.[/yellow]")
                
                rf_confidence_str = f" (Confidence: {rf_confidence:.2f})"
                dt_confidence_str = f" (Confidence: {dt_confidence:.2f})"

                console.print(f"[green]Random Forest Prediction:[/green] {rf_label}{rf_confidence_str}")
                console.print(f"[green]Decision Tree Prediction:[/green] {dt_label}{dt_confidence_str}")
                
                if rf_prediction != dt_prediction:
                    console.print("[orange1] ⚠️ Models disagree on classification! Manual review recommended.[/orange1]")

            except Exception as e:
                console.log(f"Error processing data: {e}")
                continue

    server.close()

if __name__ == "__main__":
    console.log("[bold cyan]Starting Manual Intrusion Detection System (IDS)...[/bold cyan]")
    train_and_save_model("nsl-kdd/KDDTrain+.txt")
    
    predefined_data = [
        # 1: Normal HTTP traffic - legitimate web browsing
        {'duration': 0, 'protocol_type': 'tcp', 'service': 'http', 'flag': 'SF',
        'src_bytes': 232, 'dst_bytes': 8153, 'land': 0, 'wrong_fragment': 0, 'urgent': 0,
        'hot': 0, 'num_failed_logins': 0, 'logged_in': 1, 'num_compromised': 0, 'root_shell': 0,
        'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0,
        'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
        'count': 5, 'srv_count': 5, 'serror_rate': 0.2, 'srv_serror_rate': 0.2, 'rerror_rate': 0.0,
        'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0,
        'dst_host_count': 30, 'dst_host_srv_count': 255, 'dst_host_same_srv_rate': 1.0,
        'dst_host_diff_srv_rate': 0.0, 'dst_host_same_src_port_rate': 0.03,
        'dst_host_srv_diff_host_rate': 0.04, 'dst_host_serror_rate': 0.03,
        'dst_host_srv_serror_rate': 0.01, 'dst_host_rerror_rate': 0.0,
        'dst_host_srv_rerror_rate': 0.01},
        
        # 2: Neptune DoS attack - SYN flood attack pattern
        {'duration': 0, 'protocol_type': 'tcp', 'service': 'private', 'flag': 'S0',
        'src_bytes': 0, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 0, 'urgent': 0,
        'hot': 0, 'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0, 'root_shell': 0,
        'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0,
        'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
        'count': 117, 'srv_count': 16, 'serror_rate': 1.00, 'srv_serror_rate': 1.00,
        'rerror_rate': 0.00, 'srv_rerror_rate': 0.00, 'same_srv_rate': 0.14,
        'diff_srv_rate': 0.06, 'srv_diff_host_rate': 0.00, 'dst_host_count': 255,
        'dst_host_srv_count': 15, 'dst_host_same_srv_rate': 0.06,
        'dst_host_diff_srv_rate': 0.07, 'dst_host_same_src_port_rate': 0.00,
        'dst_host_srv_diff_host_rate': 0.00, 'dst_host_serror_rate': 1.00,
        'dst_host_srv_serror_rate': 1.00, 'dst_host_rerror_rate': 0.00,
        'dst_host_srv_rerror_rate': 0.00},

        # 3: Port scanning attack - scanning for remote job service
        {'duration': 0, 'protocol_type': 'tcp', 'service': 'remote_job', 'flag': 'S0',
        'src_bytes': 0, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 0, 'urgent': 0,
        'hot': 0, 'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0, 'root_shell': 0,
        'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0,
        'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
        'count': 270, 'srv_count': 23, 'serror_rate': 1.00, 'srv_serror_rate': 1.00,
        'rerror_rate': 0.00, 'srv_rerror_rate': 0.00, 'same_srv_rate': 0.09,
        'diff_srv_rate': 0.05, 'srv_diff_host_rate': 0.00, 'dst_host_count': 255,
        'dst_host_srv_count': 23, 'dst_host_same_srv_rate': 0.09,
        'dst_host_diff_srv_rate': 0.05, 'dst_host_same_src_port_rate': 0.00,
        'dst_host_srv_diff_host_rate': 0.00, 'dst_host_serror_rate': 1.00,
        'dst_host_srv_serror_rate': 1.00, 'dst_host_rerror_rate': 0.00,
        'dst_host_srv_rerror_rate': 0.00},

        # 4: Satan attack - stealthy port scanning with multiple services
        {'duration': 0, 'protocol_type': 'tcp', 'service': 'private', 'flag': 'S0',
        'src_bytes': 0, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 0, 'urgent': 0,
        'hot': 0, 'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0, 'root_shell': 0,
        'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0,
        'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
        'count': 133, 'srv_count': 8, 'serror_rate': 1.00, 'srv_serror_rate': 1.00,
        'rerror_rate': 0.00, 'srv_rerror_rate': 0.00, 'same_srv_rate': 0.06,
        'diff_srv_rate': 0.06, 'srv_diff_host_rate': 0.00, 'dst_host_count': 255,
        'dst_host_srv_count': 13, 'dst_host_same_srv_rate': 0.05,
        'dst_host_diff_srv_rate': 0.06, 'dst_host_same_src_port_rate': 0.00,
        'dst_host_srv_diff_host_rate': 0.00, 'dst_host_serror_rate': 1.00,
        'dst_host_srv_serror_rate': 1.00, 'dst_host_rerror_rate': 0.00,
        'dst_host_srv_rerror_rate': 0.00},

        # 5: Portsweep attack - TCP connection rejection pattern
        {'duration': 0, 'protocol_type': 'tcp', 'service': 'private', 'flag': 'REJ',
        'src_bytes': 0, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 0, 'urgent': 0,
        'hot': 0, 'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0, 'root_shell': 0,
        'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0,
        'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
        'count': 205, 'srv_count': 12, 'serror_rate': 0.00, 'srv_serror_rate': 0.00,
        'rerror_rate': 1.00, 'srv_rerror_rate': 1.00, 'same_srv_rate': 0.06,
        'diff_srv_rate': 0.06, 'srv_diff_host_rate': 0.00, 'dst_host_count': 255,
        'dst_host_srv_count': 12, 'dst_host_same_srv_rate': 0.05,
        'dst_host_diff_srv_rate': 0.07, 'dst_host_same_src_port_rate': 0.00,
        'dst_host_srv_diff_host_rate': 0.00, 'dst_host_serror_rate': 0.00,
        'dst_host_srv_serror_rate': 0.00, 'dst_host_rerror_rate': 1.00,
        'dst_host_srv_rerror_rate': 1.00},

        # 6: Smurf attack - ICMP echo request flooding
        {'duration': 0, 'protocol_type': 'tcp', 'service': 'private', 'flag': 'S0',
        'src_bytes': 0, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 0, 'urgent': 0,
        'hot': 0, 'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0, 'root_shell': 0,
        'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0,
        'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
        'count': 199, 'srv_count': 3, 'serror_rate': 1.00, 'srv_serror_rate': 1.00,
        'rerror_rate': 0.00, 'srv_rerror_rate': 0.00, 'same_srv_rate': 0.02,
        'diff_srv_rate': 0.06, 'srv_diff_host_rate': 0.00, 'dst_host_count': 255,
        'dst_host_srv_count': 13, 'dst_host_same_srv_rate': 0.05,
        'dst_host_diff_srv_rate': 0.07, 'dst_host_same_src_port_rate': 0.00,
        'dst_host_srv_diff_host_rate': 0.00, 'dst_host_serror_rate': 1.00,
        'dst_host_srv_serror_rate': 1.00, 'dst_host_rerror_rate': 0.00,
        'dst_host_srv_rerror_rate': 0.00},

        # 7: Normal HTTP traffic - typical web browsing session
        {'duration': 0, 'protocol_type': 'tcp', 'service': 'http', 'flag': 'SF',
        'src_bytes': 287, 'dst_bytes': 2251, 'land': 0, 'wrong_fragment': 0, 'urgent': 0,
        'hot': 0, 'num_failed_logins': 0, 'logged_in': 1, 'num_compromised': 0, 'root_shell': 0,
        'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0,
        'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
        'count': 3, 'srv_count': 7, 'serror_rate': 0.00, 'srv_serror_rate': 0.00,
        'rerror_rate': 0.00, 'srv_rerror_rate': 0.00, 'same_srv_rate': 1.00,
        'diff_srv_rate': 0.00, 'srv_diff_host_rate': 0.43, 'dst_host_count': 8,
        'dst_host_srv_count': 219, 'dst_host_same_srv_rate': 1.00,
        'dst_host_diff_srv_rate': 0.00, 'dst_host_same_src_port_rate': 0.12,
        'dst_host_srv_diff_host_rate': 0.03, 'dst_host_serror_rate': 0.00,
        'dst_host_srv_serror_rate': 0.00, 'dst_host_rerror_rate': 0.00,
        'dst_host_srv_rerror_rate': 0.00}
    ]

    console.log("[bold cyan]Loading models and preprocessors...[/bold cyan]")
    scaler = joblib.load("scaler.pkl")
    encoder = joblib.load("encoder.pkl")
    rf_model = joblib.load("rf_model.pkl")
    dt_model = joblib.load("dt_model.pkl")

    while True:
        console.print("\n[bold yellow]Manual IDS Menu[/bold yellow]")
        console.print("Enter a number (1-8) to simulate data:")
        console.print("1 - 7: Predefined scenarios")
        console.print("8: Capture live data")
        console.print("0: Exit")

        user_input = input("Your choice: ")

        try:
            choice = int(user_input)
        except ValueError:
            console.print("[red]Invalid input. Please enter a number.[/red]")
            continue

        if choice == 0:
            console.log("[bold cyan]Exiting Manual IDS. Goodbye![/bold cyan]")
            break

        if 1 <= choice <= len(predefined_data):
            console.log(f"[bold cyan]Processing choice {choice}...[/bold cyan]")

            test_data = pd.DataFrame([predefined_data[choice - 1]])

            console.log("Preprocessing input data...")
            test_data = preprocess(test_data, is_train=False)

            console.log("Making predictions...")
            rf_prediction = rf_model.predict(test_data)[0]
            dt_prediction = dt_model.predict(test_data)[0]

            rf_label = "✅ Normal traffic" if rf_prediction == 0 else "[red]🚨 ALERT: Attack detected![/red]"
            dt_label = "✅ Normal traffic" if dt_prediction == 0 else "[red]🚨 ALERT: Attack detected![/red]"
            console.print(f"[green]Random Forest Prediction:[/green] {rf_label}")
            console.print(f"[green]Decision Tree Prediction:[/green] {dt_label}")
        elif choice == 8:
            console.log("[bold cyan]Capturing live data...[/bold cyan]")
            handle_live_data()
            
        else:
            console.print("[red]Invalid choice. Please select a number between 1 and 10.[/red]")