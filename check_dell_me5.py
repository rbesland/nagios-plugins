import requests
import json
import urllib3
import argparse
import sys
from urllib3.exceptions import InsecureRequestWarning

# Désactiver les avertissements SSL pour les certificats auto-signés
urllib3.disable_warnings(InsecureRequestWarning)

# Codes de retour NAGIOS/Centreon
NAGIOS_OK = 0
NAGIOS_WARNING = 1
NAGIOS_CRITICAL = 2
NAGIOS_UNKNOWN = 3

class RedfishClient:
    def __init__(self, ip_address, username, password, verbose=False):
        self.ip_address = ip_address
        self.username = username
        self.password = password
        self.auth_token = None
        self.base_url = f"https://{ip_address}"
        self.verbose = verbose
        
        # Compteurs pour les métriques
        self.metrics = {}
        self.status_messages = []
        self.performance_data = []
        
    def log_verbose(self, message):
        """Log uniquement en mode verbose"""
        if self.verbose:
            print(message)
    
    def authenticate(self):
        """Authentification et récupération du token X-Auth-Token"""
        url = f"{self.base_url}/redfish/v1/SessionService/Sessions"
        
        payload = {
            "UserName": self.username,
            "Password": self.password
        }
        
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        try:
            self.log_verbose(f"Authentification sur {self.ip_address}...")
            
            response = requests.post(
                url,
                data=json.dumps(payload),
                headers=headers,
                verify=False,
                timeout=120
            )
            
            if response.status_code in [200, 201]:
                self.auth_token = response.headers.get('X-Auth-Token')
                
                if self.auth_token:
                    self.log_verbose("Authentification réussie")
                    return True
                else:
                    self.status_messages.append("UNKNOWN - Token X-Auth-Token non trouvé")
                    return False
            else:
                self.status_messages.append(f"UNKNOWN - Échec authentification (Code: {response.status_code})")
                return False
                
        except Exception as e:
            self.status_messages.append(f"UNKNOWN - Erreur authentification: {str(e)}")
            return False
    
    def make_authenticated_request(self, endpoint):
        """Effectue une requête GET avec le token d'authentification"""
        if not self.auth_token:
            return None
        
        url = f"{self.base_url}{endpoint}"
        headers = {
            "X-Auth-Token": self.auth_token,
            "Accept": "application/json"
        }
        
        try:
            response = requests.get(url, headers=headers, verify=False, timeout=120)
            if response.status_code == 200:
                return response.json()
            else:
                self.log_verbose(f"Erreur {response.status_code} pour {endpoint}")
                return None
        except Exception as e:
            self.log_verbose(f"Erreur requête {endpoint}: {e}")
            return None
    
    def get_chassis_list(self):
        """Récupère la liste des châssis"""
        chassis_data = self.make_authenticated_request("/redfish/v1/Chassis")
        if chassis_data and "Members" in chassis_data:
            return [member["@odata.id"] for member in chassis_data["Members"]]
        return []
    
    def get_storage_list(self):
        """Récupère la liste des contrôleurs de stockage"""
        storage_data = self.make_authenticated_request("/redfish/v1/Storage")
        if storage_data and "Members" in storage_data:
            return [member["@odata.id"] for member in storage_data["Members"]]
        return []
    
    def check_thermal(self):
        """Vérification des ventilateurs uniquement"""
        chassis_list = self.get_chassis_list()
        
        fans_ok = fans_warning = fans_critical = fans_unknown = 0
        fan_details = []
        
        for chassis_endpoint in chassis_list:
            thermal_data = self.make_authenticated_request(f"{chassis_endpoint}/Thermal")
            
            if not thermal_data:
                fans_unknown += 1
                continue
            
            # Vérification des ventilateurs uniquement
            for fan in thermal_data.get("Fans", []):
                fan_name = fan.get("Name", f"Fan {fan.get('MemberId', 'Unknown')}")
                fan_health = fan.get("Status", {}).get("Health", "Unknown")
                fan_state = fan.get("Status", {}).get("State", "Unknown")
                fan_speed = fan.get("Reading", 0)
                
                if fan_health == "OK" and fan_state == "Enabled":
                    fans_ok += 1
                elif fan_health == "Warning":
                    fans_warning += 1
                    fan_details.append(f"{fan_name} (WARNING)")
                elif fan_health == "Critical":
                    fans_critical += 1
                    fan_details.append(f"{fan_name} (CRITICAL)")
                else:
                    fans_unknown += 1
                    fan_details.append(f"{fan_name} (UNKNOWN)")
                
                # Ajout des données de performance pour les ventilateurs (sans seuils)
                self.performance_data.append(f"'{fan_name}_rpm'={fan_speed}rpm;;;0;")
        
        # Détermination du statut global
        if fans_critical > 0:
            status = "CRITICAL"
            exit_code = NAGIOS_CRITICAL
        elif fans_warning > 0:
            status = "WARNING" 
            exit_code = NAGIOS_WARNING
        elif fans_unknown > 0:
            status = "UNKNOWN"
            exit_code = NAGIOS_UNKNOWN
        else:
            status = "OK"
            exit_code = NAGIOS_OK
        
        # Construction du message
        total_fans = fans_ok + fans_warning + fans_critical + fans_unknown
        
        message = f"{status} - Fans: {total_fans} total ({fans_ok} OK, {fans_warning} WARN, {fans_critical} CRIT)"
        
        if fan_details:
            message += " | Issues: " + ", ".join(fan_details)
        
        return exit_code, message
    
    def check_power(self):
        """Vérification des alimentations"""
        chassis_list = self.get_chassis_list()
        
        psu_ok = psu_warning = psu_critical = psu_unknown = 0
        voltage_ok = voltage_warning = voltage_critical = voltage_unknown = 0
        
        psu_details = []
        voltage_details = []
        
        for chassis_endpoint in chassis_list:
            power_data = self.make_authenticated_request(f"{chassis_endpoint}/Power")
            
            if not power_data:
                psu_unknown += 1
                voltage_unknown += 1
                continue
            
            # Vérification des PSU
            for psu in power_data.get("PowerSupplies", []):
                psu_name = psu.get("Name", f"PSU {psu.get('MemberId', 'Unknown')}")
                psu_health = psu.get("Status", {}).get("Health", "Unknown")
                psu_state = psu.get("Status", {}).get("State", "Unknown")
                
                if psu_health == "OK" and psu_state == "Enabled":
                    psu_ok += 1
                elif psu_health == "Warning":
                    psu_warning += 1
                    psu_details.append(f"{psu_name} (WARNING)")
                elif psu_health == "Critical":
                    psu_critical += 1
                    psu_details.append(f"{psu_name} (CRITICAL)")
                else:
                    psu_unknown += 1
                    psu_details.append(f"{psu_name} (UNKNOWN)")
            
            # Vérification des tensions
            for voltage in power_data.get("Voltages", []):
                voltage_name = voltage.get("Name", f"Voltage {voltage.get('MemberId', 'Unknown')}")
                voltage_health = voltage.get("Status", {}).get("Health", "Unknown")
                voltage_state = voltage.get("Status", {}).get("State", "Unknown")
                voltage_reading = voltage.get("ReadingVolts", 0)
                
                if voltage_health == "OK" and voltage_state == "Enabled":
                    voltage_ok += 1
                elif voltage_health == "Warning":
                    voltage_warning += 1
                    voltage_details.append(f"{voltage_name} (WARNING)")
                elif voltage_health == "Critical":
                    voltage_critical += 1
                    voltage_details.append(f"{voltage_name} (CRITICAL)")
                else:
                    voltage_unknown += 1
                    voltage_details.append(f"{voltage_name} (UNKNOWN)")
                
                # Ajout des données de performance pour les tensions
                self.performance_data.append(f"'{voltage_name}_volts'={voltage_reading}V;;;0;")
        
        # Détermination du statut global
        if psu_critical > 0 or voltage_critical > 0:
            status = "CRITICAL"
            exit_code = NAGIOS_CRITICAL
        elif psu_warning > 0 or voltage_warning > 0:
            status = "WARNING"
            exit_code = NAGIOS_WARNING
        elif psu_unknown > 0 or voltage_unknown > 0:
            status = "UNKNOWN"
            exit_code = NAGIOS_UNKNOWN
        else:
            status = "OK"
            exit_code = NAGIOS_OK
        
        # Construction du message
        total_psu = psu_ok + psu_warning + psu_critical + psu_unknown
        total_voltages = voltage_ok + voltage_warning + voltage_critical + voltage_unknown
        
        message = f"{status} - PSU: {total_psu} total ({psu_ok} OK, {psu_warning} WARN, {psu_critical} CRIT), "
        message += f"Voltages: {total_voltages} total ({voltage_ok} OK, {voltage_warning} WARN, {voltage_critical} CRIT)"
        
        if psu_details or voltage_details:
            message += " | Issues: " + ", ".join(psu_details + voltage_details)
        
        return exit_code, message
    
    def check_controllers(self):
        """Vérification des contrôleurs de stockage"""
        storage_list = self.get_storage_list()
        
        ctrl_ok = ctrl_warning = ctrl_critical = ctrl_unknown = 0
        ctrl_details = []
        
        for storage_endpoint in storage_list:
            storage_data = self.make_authenticated_request(storage_endpoint)
            
            if not storage_data:
                ctrl_unknown += 1
                continue
            
            # Vérification du contrôleur principal
            storage_health = storage_data.get("Status", {}).get("Health", "Unknown")
            storage_name = storage_data.get("Name", storage_endpoint.split('/')[-1])
            
            if storage_health == "OK":
                ctrl_ok += 1
            elif storage_health == "Warning":
                ctrl_warning += 1
                ctrl_details.append(f"{storage_name} (WARNING)")
            elif storage_health == "Critical":
                ctrl_critical += 1
                ctrl_details.append(f"{storage_name} (CRITICAL)")
            else:
                ctrl_unknown += 1
                ctrl_details.append(f"{storage_name} (UNKNOWN)")
        
        # Détermination du statut global
        if ctrl_critical > 0:
            status = "CRITICAL"
            exit_code = NAGIOS_CRITICAL
        elif ctrl_warning > 0:
            status = "WARNING"
            exit_code = NAGIOS_WARNING
        elif ctrl_unknown > 0:
            status = "UNKNOWN"
            exit_code = NAGIOS_UNKNOWN
        else:
            status = "OK"
            exit_code = NAGIOS_OK
        
        # Construction du message
        total_controllers = ctrl_ok + ctrl_warning + ctrl_critical + ctrl_unknown
        
        message = f"{status} - Controllers: {total_controllers} total ({ctrl_ok} OK, {ctrl_warning} WARN, {ctrl_critical} CRIT)"
        
        if ctrl_details:
            message += " | Issues: " + ", ".join(ctrl_details)
        
        return exit_code, message
    
    def check_disks(self):
        """Vérification des disques"""
        storage_list = self.get_storage_list()
        
        disk_ok = disk_warning = disk_critical = disk_unknown = 0
        disk_details = []
        
        for storage_endpoint in storage_list:
            storage_data = self.make_authenticated_request(storage_endpoint)
            
            if not storage_data:
                continue
            
            # Récupération des disques
            drives = storage_data.get("Drives", [])
            
            for drive_ref in drives:
                drive_endpoint = drive_ref.get("@odata.id")
                if not drive_endpoint:
                    continue
                
                drive_data = self.make_authenticated_request(drive_endpoint)
                
                if not drive_data:
                    disk_unknown += 1
                    continue
                
                drive_name = drive_data.get("Name", drive_endpoint.split('/')[-1])
                drive_health = drive_data.get("Status", {}).get("Health", "Unknown")
                drive_state = drive_data.get("Status", {}).get("State", "Unknown")
                drive_capacity = drive_data.get("CapacityBytes", 0)
                drive_model = drive_data.get("PartNumber", "Unknown")  # Utilisation de PartNumber pour le modèle
                
                if drive_health == "OK" and drive_state in ["Activé"]:
                    disk_ok += 1
                elif drive_health == "Warning":
                    disk_warning += 1
                    disk_details.append(f"{drive_name} ({drive_model}) (WARNING)")
                elif drive_health == "Critical":
                    disk_critical += 1
                    disk_details.append(f"{drive_name} ({drive_model}) (CRITICAL)")
                else:
                    disk_unknown += 1
                    disk_details.append(f"{drive_name} ({drive_model}) (UNKNOWN)")
                
                # Ajout des données de performance pour la capacité des disques
                capacity_gb = round(drive_capacity / (1024**3), 2) if drive_capacity else 0
                self.performance_data.append(f"'{drive_name}_capacity'={capacity_gb}GB;;;0;")
        
        # Détermination du statut global
        if disk_critical > 0:
            status = "CRITICAL"
            exit_code = NAGIOS_CRITICAL
        elif disk_warning > 0:
            status = "WARNING" 
            exit_code = NAGIOS_WARNING
        elif disk_unknown > 0:
            status = "UNKNOWN"
            exit_code = NAGIOS_UNKNOWN
        else:
            status = "OK"
            exit_code = NAGIOS_OK
        
        # Construction du message
        total_disks = disk_ok + disk_warning + disk_critical + disk_unknown
        
        message = f"{status} - Disks: {total_disks} total ({disk_ok} OK, {disk_warning} WARN, {disk_critical} CRIT)"
        
        if disk_details:
            message += " | Issues: " + ", ".join(disk_details)
        
        return exit_code, message
    
    def check_all(self):
        """Vérification complète de tous les composants"""
        results = {}
        
        # Vérification de chaque composant
        results['thermal'] = self.check_thermal()
        results['power'] = self.check_power()  
        results['controllers'] = self.check_controllers()
        results['disks'] = self.check_disks()
        
        # Détermination du statut global (pire statut)
        exit_codes = [result[0] for result in results.values()]
        max_exit_code = max(exit_codes) if exit_codes else NAGIOS_UNKNOWN
        
        # Mapping des codes vers les statuts
        status_map = {
            NAGIOS_OK: "OK",
            NAGIOS_WARNING: "WARNING", 
            NAGIOS_CRITICAL: "CRITICAL",
            NAGIOS_UNKNOWN: "UNKNOWN"
        }
        
        global_status = status_map.get(max_exit_code, "UNKNOWN")
        
        # Construction du message global
        messages = []
        for component, (code, message) in results.items():
            component_status = message.split(' - ')[0]
            component_details = message.split(' - ')[1] if ' - ' in message else ""
            messages.append(f"{component.upper()}: {component_details}")
        
        final_message = f"{global_status} - " + " | ".join(messages)
        
        return max_exit_code, final_message

def main():
    parser = argparse.ArgumentParser(
        description="Plugin Centreon pour surveillance Redfish",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes de vérification:
  thermal     - Ventilateurs uniquement
  power       - Alimentations et tensions  
  controller  - Contrôleurs de stockage
  disk        - Disques durs
  all         - Tous les composants

Exemples d'utilisation:
  python redfish_check.py -H 172.30.100.111 -u admin -p password -m thermal
  python redfish_check.py -H 172.30.100.111 -u admin -p password -m all -v
        """
    )
    
    parser.add_argument('-H', '--hostname', required=True, help='Adresse IP ou nom d\'hôte')
    parser.add_argument('-u', '--username', required=True, help='Nom d\'utilisateur')
    parser.add_argument('-p', '--password', required=True, help='Mot de passe')
    parser.add_argument('-m', '--mode', 
                      choices=['thermal', 'power', 'controller', 'disk', 'all'],
                      default='all',
                      help='Mode de vérification (défaut: all)')
    parser.add_argument('-v', '--verbose', action='store_true', 
                      help='Mode verbeux pour le débogage')
    parser.add_argument('-t', '--timeout', type=int, default=120,
                      help='Timeout en secondes (défaut: 120)')
    
    args = parser.parse_args()
    
    # Création du client Redfish
    client = RedfishClient(args.hostname, args.username, args.password, args.verbose)
    
    # Authentification
    if not client.authenticate():
        print("UNKNOWN - Échec de l'authentification")
        sys.exit(NAGIOS_UNKNOWN)
    
    # Exécution de la vérification selon le mode
    try:
        if args.mode == 'thermal':
            exit_code, message = client.check_thermal()
        elif args.mode == 'power':
            exit_code, message = client.check_power()
        elif args.mode == 'controller':
            exit_code, message = client.check_controllers()
        elif args.mode == 'disk':
            exit_code, message = client.check_disks()
        elif args.mode == 'all':
            exit_code, message = client.check_all()
        else:
            print("UNKNOWN - Mode non supporté")
            sys.exit(NAGIOS_UNKNOWN)
        
        # Affichage du résultat avec données de performance
        if client.performance_data:
            print(f"{message} | {' '.join(client.performance_data)}")
        else:
            print(message)
        
        sys.exit(exit_code)
        
    except Exception as e:
        print(f"UNKNOWN - Erreur inattendue: {str(e)}")
        sys.exit(NAGIOS_UNKNOWN)

if __name__ == "__main__":
    main()
