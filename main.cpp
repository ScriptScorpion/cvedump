// requires nlohmann-json3-dev
// file with cves inside located in /opt/cvedump
#include <nlohmann/json.hpp>
#include <iostream>
#include <string>
#include <sstream>
#include <filesystem>
#include <fstream>
#include <cstdlib>
#include <cstring>
#ifdef __unix__
    #include <unistd.h>
#else 
    std::exit(2);
#endif


std::string float_to_string(const double &value) {
    std::stringstream s;
    s << value;
    return s.str();
}
struct Msg_structure {
    std::string severity = ""; // TODO
    std::string affected = ""; 
    std::string cveid = "";
    std::string impact = "";
    std::string references = "";
    std::string state = "";
    std::string description = "";
};
void display_help() {
    std::cout << 
    "Usage: cvedump [option] \"word\"\n\n" 
    "Options:\n"
    "\tsearch\n"
    "\tlist\n"
    "\tupdate\n" 
    << std::endl;
}
int main(int argc, char *argv[]) {
    if (argc != 2 && argc != 3) {
        display_help();
        return 1;
    }
    if (strcmp(argv[1], "update") == 0 && argc == 2) {
        if (getuid() != 0) {
            std::cerr << "Error: update requires root priveleges (try running command with sudo)" << std::endl;
            return 1;
        }
        else {
            if (!std::filesystem::exists("/opt/cvedump")) {
                system("mkdir /opt/cvedump");
            }
            const std::string combiner = "cd " + (std::filesystem::current_path().string());
            system("cd /opt/cvedump && wget -q -O main.zip https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip && unzip -qq main.zip && rm -f main.zip && mv cvelistV5-main/* . && rm -rf cvelistV5-main");
            system(combiner.c_str());
            return 0;
        }
    }
    else if (strcmp(argv[1], "list") == 0 && argc == 2) {
        if (!std::filesystem::exists("/opt/cvedump/cves")) {
            std::cerr << "Error: CVE folder don't exists" << std::endl;
            return 1;
        }
        for (const std::filesystem::directory_entry &de : std::filesystem::recursive_directory_iterator("/opt/cvedump/cves")) {
            if (std::filesystem::is_regular_file(de.path())) { 
                if (de.path().extension() != ".json" || de.path() == "/opt/cvedump/cves/deltaLog.json" || de.path() == "/opt/cvedump/cves/delta.json") {
                    continue;
                }
                std::ifstream reader(de.path());
                if (!reader) {
                    std::cerr << "Error while reading file: " << de.path() << std::endl;
                    continue;
                }
                Msg_structure *Json_file = new Msg_structure();
                auto json_data = nlohmann::json::parse(reader);

                if (json_data.is_array()) {
                    Json_file->cveid = json_data[0]["cveId"];
                    Json_file->state = json_data[0]["state"];
                    
                    if (Json_file->state == "PUBLISHED") {
                        
                        Json_file->description = json_data[1]["cna"]["descriptions"][0]["value"];

                        if (!json_data[1]["cna"]["affected"][0]["product"].is_null()) {
                            if (std::string(json_data[1]["cna"]["affected"][0]["product"]) != "n/a") {
                                Json_file->affected += '\n';
                                for (size_t j = 0; j < json_data[1]["cna"]["affected"].size(); ++j) {
                                    
                                    Json_file->affected += std::to_string(j+1) + ". " + std::string(json_data[1]["cna"]["affected"][j]["product"]);
                                    
                                    if (!(json_data[1]["cna"]["affected"][j]["versions"][0]["lessThanOrEqual"].is_null())) {
                                        Json_file->affected += " <= " + std::string(json_data[1]["cna"]["affected"][j]["versions"][0]["lessThanOrEqual"]);
                                    }
                                    else if (!(json_data[1]["cna"]["affected"][j]["versions"][0]["lessThan"].is_null())) {
                                        Json_file->affected += " < " + std::string(json_data[1]["cna"]["affected"][j]["versions"][0]["lessThan"]);
                                    }
                                    else if (!(json_data[1]["cna"]["affected"][j]["versions"][0]["version"].is_null())) {
                                        Json_file->affected += " = " + std::string(json_data[1]["cna"]["affected"][j]["versions"][0]["version"]);
                                    }
                                    if (j+1 != json_data[1]["cna"]["affected"].size()) {
                                        Json_file->affected += '\n';
                                    }
                                }
                            }
                        }

                        if (!json_data[1]["cna"]["metrics"].is_null()) {
                            if (!json_data[1]["cna"]["metrics"][0]["cvssV4_0"].is_null()) {
                                if (!json_data[1]["cna"]["metrics"][0]["cvssV4_0"]["baseScore"].is_null() && !json_data[1]["cna"]["metrics"][0]["cvssV4_0"]["baseSeverity"].is_null()) {
                                    Json_file->severity = float_to_string(json_data[1]["cna"]["metrics"][0]["cvssV4_0"]["baseScore"].get<double>()) + " " + std::string(json_data[1]["cna"]["metrics"][0]["cvssV4_0"]["baseSeverity"]) + " (CVSS V4_0)"; 
                                }
                            }
                            else if (!json_data[1]["cna"]["metrics"][0]["cvssV3_1"].is_null()) {
                                if (!json_data[1]["cna"]["metrics"][0]["cvssV3_1"]["baseScore"].is_null() && !json_data[1]["cna"]["metrics"][0]["cvssV3_1"]["baseSeverity"].is_null()) {
                                    Json_file->severity = float_to_string(json_data[1]["cna"]["metrics"][0]["cvssV3_1"]["baseScore"].get<double>()) + " " + std::string(json_data[1]["cna"]["metrics"][0]["cvssV3_1"]["baseSeverity"]) + " (CVSS V3_1)"; 
                                }
                            }
                            else if (!json_data[1]["cna"]["metrics"][0]["cvssV3_0"].is_null()) {
                                if (!json_data[1]["cna"]["metrics"][0]["cvssV3_0"]["baseScore"].is_null() && !json_data[1]["cna"]["metrics"][0]["cvssV3_0"]["baseSeverity"].is_null()) {
                                    Json_file->severity = float_to_string(json_data[1]["cna"]["metrics"][0]["cvssV3_0"]["baseScore"].get<double>()) + " " + std::string(json_data[1]["cna"]["metrics"][0]["cvssV3_0"]["baseSeverity"]) + " (CVSS V3_0)"; 
                                }
                            }
                            else if (!json_data[1]["cna"]["metrics"][0]["cvssV2_0"].is_null()) {
                                if (!json_data[1]["cna"]["metrics"][0]["cvssV2_0"]["baseScore"].is_null()) {
                                    Json_file->severity = float_to_string(json_data[1]["cna"]["metrics"][0]["cvssV2_0"]["baseScore"].get<double>()) + " (CVSS V2_0)"; 
                                }
                            }
                        }

                        if (!json_data[1]["cna"]["x_legacyV4Record"]["impact"].is_null()) {
                            if (!json_data[1]["cna"]["x_legacyV4Record"]["impact"].is_array()) {
                                if (!json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"].is_null()) {
                                    if (json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"].is_array()) {
                                        if (json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0].is_array()) {
                                            if (!json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0][0]["baseScore"].is_null() && !json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0][0]["baseSeverity"].is_null()) {
                                                Json_file->impact = (json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0][0]["baseScore"].dump()) + ' ' + std::string(json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0][0]["baseSeverity"]);    
                                            }
                                            else if (!json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0][0]["vectorString"].is_null()) {
                                                Json_file->impact = std::string(json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0][0]["vectorString"]);
                                            }
                                        }
                                        else {
                                            if (!json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0]["baseScore"].is_null() && !json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0]["baseSeverity"].is_null()) {
                                                Json_file->impact = (json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0]["baseScore"].dump()) + ' ' + std::string(json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0]["baseSeverity"]);    
                                            }
                                            else if (!json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0]["vectorString"].is_null()) {
                                                Json_file->impact = std::string(json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0]["vectorString"]);
                                            }
                                        }
                                    }
                                    else {
                                        if (!json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"]["baseScore"].is_null() && !json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"]["baseSeverity"].is_null()) {
                                            Json_file->impact = (json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"]["baseScore"].dump()) + ' ' + std::string(json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"]["baseSeverity"]);    
                                        }
                                        else if(!json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"]["vectorString"].is_null())  {
                                            Json_file->impact = std::string(json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"]["vectorString"]);
                                        }
                                    }
                                }
                            }
                        }

                        if (!json_data[1]["cna"]["references"].is_null()) {
                            Json_file->references += '\n';
                            for (size_t i = 0; i < json_data[1]["cna"]["references"].size(); ++i) {
                                Json_file->references += std::to_string(i+1) + ". " + std::string(json_data[1]["cna"]["references"][i]["url"]); 
                                if (i+1 != json_data[1]["cna"]["references"].size()) {
                                    Json_file->references += '\n';
                                }
                            }
                        }
                    }
                }
                else { 
                    Json_file->cveid = json_data["cveMetadata"]["cveId"];
                    Json_file->state = json_data["cveMetadata"]["state"];
                    if (Json_file->state == "PUBLISHED") {
                        
                        Json_file->description = json_data["containers"]["cna"]["descriptions"][0]["value"];
                        
                        if (!json_data["containers"]["cna"]["affected"][0]["product"].is_null()) {
                            if (std::string(json_data["containers"]["cna"]["affected"][0]["product"]) != "n/a") {
                                Json_file->affected += '\n';
                                for (size_t j = 0; j < json_data["containers"]["cna"]["affected"].size(); ++j) {
                                    
                                    Json_file->affected += std::to_string(j+1) + ". " + std::string(json_data["containers"]["cna"]["affected"][j]["product"]);
                                    
                                    if (!(json_data["containers"]["cna"]["affected"][j]["versions"][0]["lessThanOrEqual"].is_null())) {
                                        Json_file->affected += " <= " + std::string(json_data["containers"]["cna"]["affected"][j]["versions"][0]["lessThanOrEqual"]);
                                    }
                                    else if (!(json_data["containers"]["cna"]["affected"][j]["versions"][0]["lessThan"].is_null())) {
                                        Json_file->affected += " < " + std::string(json_data["containers"]["cna"]["affected"][j]["versions"][0]["lessThan"]);
                                    }
                                    else if (!(json_data["containers"]["cna"]["affected"][j]["versions"][0]["version"].is_null())) {
                                        Json_file->affected += " = " + std::string(json_data["containers"]["cna"]["affected"][j]["versions"][0]["version"]);
                                    }
                                    if (j+1 != json_data["containers"]["cna"]["affected"].size()) {
                                        Json_file->affected += '\n';
                                    }
                                }
                            }
                        }
                       

                        if (!json_data["containers"]["cna"]["metrics"].is_null()) {
                            if (!json_data["containers"]["cna"]["metrics"][0]["cvssV4_0"].is_null()) {
                                if (!json_data["containers"]["cna"]["metrics"][0]["cvssV4_0"]["baseScore"].is_null() && !json_data["containers"]["cna"]["metrics"][0]["cvssV4_0"]["baseSeverity"].is_null()) {
                                    Json_file->severity = float_to_string(json_data["containers"]["cna"]["metrics"][0]["cvssV4_0"]["baseScore"].get<double>()) + " " + std::string(json_data["containers"]["cna"]["metrics"][0]["cvssV4_0"]["baseSeverity"]) + " (CVSS V4_0)"; 
                                }
                            }
                            else if (!json_data["containers"]["cna"]["metrics"][0]["cvssV3_1"].is_null()) {
                                if (!json_data["containers"]["cna"]["metrics"][0]["cvssV3_1"]["baseScore"].is_null() && !json_data["containers"]["cna"]["metrics"][0]["cvssV3_1"]["baseSeverity"].is_null()) {
                                    Json_file->severity = float_to_string(json_data["containers"]["cna"]["metrics"][0]["cvssV3_1"]["baseScore"].get<double>()) + " " + std::string(json_data["containers"]["cna"]["metrics"][0]["cvssV3_1"]["baseSeverity"]) + " (CVSS V3_1)"; 
                                }
                            }
                            else if (!json_data["containers"]["cna"]["metrics"][0]["cvssV3_0"].is_null()) {
                                if (!json_data["containers"]["cna"]["metrics"][0]["cvssV3_0"]["baseScore"].is_null() && !json_data["containers"]["cna"]["metrics"][0]["cvssV3_0"]["baseSeverity"].is_null()) {
                                    Json_file->severity = float_to_string(json_data["containers"]["cna"]["metrics"][0]["cvssV3_0"]["baseScore"].get<double>()) + " " + std::string(json_data["containers"]["cna"]["metrics"][0]["cvssV3_0"]["baseSeverity"]) + " (CVSS V3_0)"; 
                                }
                            }
                            else if (!json_data["containers"]["cna"]["metrics"][0]["cvssV2_0"].is_null()) {
                                if (!json_data["containers"]["cna"]["metrics"][0]["cvssV2_0"]["baseScore"].is_null()) {
                                    Json_file->severity = float_to_string(json_data["containers"]["cna"]["metrics"][0]["cvssV2_0"]["baseScore"].get<double>()) + " (CVSS V2_0)"; 
                                }
                            }
                        }


                        if (!json_data["containers"]["cna"]["x_legacyV4Record"]["impact"].is_null()) {
                            if (!json_data["containers"]["cna"]["x_legacyV4Record"]["impact"].is_array()) {
                                if (!json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"].is_null()) {
                                    if (json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"].is_array()) {
                                        if (json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0].is_array()) {
                                            if (!json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0][0]["baseScore"].is_null() && !json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0][0]["baseSeverity"].is_null()) {
                                                Json_file->impact = (json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0][0]["baseScore"].dump()) + ' ' + std::string(json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0][0]["baseSeverity"]);    
                                            }
                                            else if (!json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0][0]["vectorString"].is_null()) {
                                                Json_file->impact = std::string(json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0][0]["vectorString"]);
                                            }
                                        }
                                        else {
                                            if (!json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0]["baseScore"].is_null() && !json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0]["baseSeverity"].is_null()) {
                                                Json_file->impact = (json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0]["baseScore"].dump()) + ' ' + std::string(json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0]["baseSeverity"]);    
                                            }
                                            else if (!json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0]["vectorString"].is_null()) {
                                                Json_file->impact = std::string(json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0]["vectorString"]);
                                            }
                                        }
                                    }
                                    else {
                                        if (!json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"]["baseScore"].is_null() && !json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"]["baseSeverity"].is_null()) {
                                            Json_file->impact = (json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"]["baseScore"].dump()) + ' ' + std::string(json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"]["baseSeverity"]);    
                                        }
                                        else if (!json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"]["vectorString"].is_null()) {
                                            Json_file->impact = std::string(json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"]["vectorString"]);
                                        }
                                    }
                                }
                            }
                        }

                        if (!json_data["containers"]["cna"]["references"].is_null()) {
                            Json_file->references += '\n';
                            for (size_t i = 0; i < json_data["containers"]["cna"]["references"].size(); ++i) {
                                Json_file->references += std::to_string(i+1) + ". " + std::string(json_data["containers"]["cna"]["references"][i]["url"]) + '\n';
                            }
                        }
                    }
                }
                std::cout << "Status: " << Json_file->state << '\n';
                std::cout << "CVE id: " << Json_file->cveid << '\n';
                std::cout << "Impact: " << Json_file->impact << '\n';
                std::cout << "Severity: " << Json_file->severity << '\n';
                std::cout << "Affected: " << Json_file->affected << '\n';
                std::cout << "Raw data: " << de.path().string() << '\n';
                std::cout << "References: " << Json_file->references;
                std::cout << "Description: " << Json_file->description << "\n\n\n\n\n";
                delete Json_file;
                reader.close();
            }
        }
    }
    else if (strcmp(argv[1], "search") == 0 && argc == 3) {
        if (!std::filesystem::exists("/opt/cvedump/cves")) {
            std::cerr << "Error: CVE folder don't exists" << std::endl;
            return 1;
        }
        for (const std::filesystem::directory_entry &de : std::filesystem::recursive_directory_iterator("/opt/cvedump/cves")) {
            if (std::filesystem::is_regular_file(de.path())) { 
                if (de.path().extension() != ".json" || de.path() == "/opt/cvedump/cves/deltaLog.json" || de.path() == "/opt/cvedump/cves/delta.json") {
                    continue;
                }
                std::ifstream reader(de.path());
                if (!reader) {
                    std::cerr << "Error while reading file: " << de.path() << std::endl;
                    continue;
                }
                Msg_structure *Json_file = new Msg_structure();
                auto json_data = nlohmann::json::parse(reader);
                if (json_data.is_array()) {
                    Json_file->cveid = json_data[0]["cveId"];
                    Json_file->state = json_data[0]["state"];
                    if (Json_file->state == "PUBLISHED") {
                        
                        Json_file->description = json_data[1]["cna"]["descriptions"][0]["value"];
                        
                        if (!json_data[1]["cna"]["affected"][0]["product"].is_null()) {
                            if (std::string(json_data[1]["cna"]["affected"][0]["product"]) != "n/a") {
                                Json_file->affected += '\n';
                                for (size_t j = 0; j < json_data[1]["cna"]["affected"].size(); ++j) {
                                    
                                    Json_file->affected += std::to_string(j+1) + ". " + std::string(json_data[1]["cna"]["affected"][j]["product"]);
                                    
                                    if (!(json_data[1]["cna"]["affected"][j]["versions"][0]["lessThanOrEqual"].is_null())) {
                                        Json_file->affected += " <= " + std::string(json_data[1]["cna"]["affected"][j]["versions"][0]["lessThanOrEqual"]);
                                    }
                                    else if (!(json_data[1]["cna"]["affected"][j]["versions"][0]["lessThan"].is_null())) {
                                        Json_file->affected += " < " + std::string(json_data[1]["cna"]["affected"][j]["versions"][0]["lessThan"]);
                                    }
                                    else if (!(json_data[1]["cna"]["affected"][j]["versions"][0]["version"].is_null())) {
                                        Json_file->affected += " = " + std::string(json_data[1]["cna"]["affected"][j]["versions"][0]["version"]);
                                    }
                                    if (j+1 != json_data[1]["cna"]["affected"].size()) {
                                        Json_file->affected += '\n';
                                    }
                                }
                            }
                        }

                        if (!json_data[1]["cna"]["metrics"].is_null()) {
                            if (!json_data[1]["cna"]["metrics"][0]["cvssV4_0"].is_null()) {
                                if (!json_data[1]["cna"]["metrics"][0]["cvssV4_0"]["baseScore"].is_null() && !json_data[1]["cna"]["metrics"][0]["cvssV4_0"]["baseSeverity"].is_null()) {
                                    Json_file->severity = float_to_string(json_data[1]["cna"]["metrics"][0]["cvssV4_0"]["baseScore"].get<double>()) + " " + std::string(json_data[1]["cna"]["metrics"][0]["cvssV4_0"]["baseSeverity"]) + " (CVSS V4_0)"; 
                                }
                            }
                            else if (!json_data[1]["cna"]["metrics"][0]["cvssV3_1"].is_null()) {
                                if (!json_data[1]["cna"]["metrics"][0]["cvssV3_1"]["baseScore"].is_null() && !json_data[1]["cna"]["metrics"][0]["cvssV3_1"]["baseSeverity"].is_null()) {
                                    Json_file->severity = float_to_string(json_data[1]["cna"]["metrics"][0]["cvssV3_1"]["baseScore"].get<double>()) + " " + std::string(json_data[1]["cna"]["metrics"][0]["cvssV3_1"]["baseSeverity"]) + " (CVSS V3_1)"; 
                                }
                            }
                            else if (!json_data[1]["cna"]["metrics"][0]["cvssV3_0"].is_null()) {
                                if (!json_data[1]["cna"]["metrics"][0]["cvssV3_0"]["baseScore"].is_null() && !json_data[1]["cna"]["metrics"][0]["cvssV3_0"]["baseSeverity"].is_null()) {
                                    Json_file->severity = float_to_string(json_data[1]["cna"]["metrics"][0]["cvssV3_0"]["baseScore"].get<double>()) + " " + std::string(json_data[1]["cna"]["metrics"][0]["cvssV3_0"]["baseSeverity"]) + " (CVSS V3_0)"; 
                                }
                            }
                            else if (!json_data[1]["cna"]["metrics"][0]["cvssV2_0"].is_null()) {
                                if (!json_data[1]["cna"]["metrics"][0]["cvssV2_0"]["baseScore"].is_null()) {
                                    Json_file->severity = float_to_string(json_data[1]["cna"]["metrics"][0]["cvssV2_0"]["baseScore"].get<double>()) + " (CVSS V2_0)"; 
                                }
                            }
                        }

                        if (!json_data[1]["cna"]["x_legacyV4Record"]["impact"].is_null()) {
                            if (!json_data[1]["cna"]["x_legacyV4Record"]["impact"].is_array()) {
                                if (!json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"].is_null()) {
                                    if (json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"].is_array()) {
                                        if (json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0].is_array()) {
                                            if (!json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0][0]["baseScore"].is_null() && !json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0][0]["baseSeverity"].is_null()) {
                                                Json_file->impact = (json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0][0]["baseScore"].dump()) + ' ' + std::string(json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0][0]["baseSeverity"]);    
                                            }
                                            else if (!json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0][0]["vectorString"].is_null()) {
                                                Json_file->impact = std::string(json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0][0]["vectorString"]);
                                            }
                                        }
                                        else {
                                            if (!json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0]["baseScore"].is_null() && !json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0]["baseSeverity"].is_null()) {
                                                Json_file->impact = (json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0]["baseScore"].dump()) + ' ' + std::string(json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0]["baseSeverity"]);    
                                            }
                                            else if (!json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0]["vectorString"].is_null()) {
                                                Json_file->impact = std::string(json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0]["vectorString"]);
                                            }
                                        }
                                    }
                                    else {
                                        if (!json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"]["baseScore"].is_null() && !json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"]["baseSeverity"].is_null()) {
                                            Json_file->impact = (json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"]["baseScore"].dump()) + ' ' + std::string(json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"]["baseSeverity"]);    
                                        }
                                        else if(!json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"]["vectorString"].is_null())  {
                                            Json_file->impact = std::string(json_data[1]["cna"]["x_legacyV4Record"]["impact"]["cvss"]["vectorString"]);
                                        }
                                    }
                                }
                            }
                        }

                        if (!json_data[1]["cna"]["references"].is_null()) {
                            Json_file->references += '\n';
                            for (size_t i = 0; i < json_data[1]["cna"]["references"].size(); ++i) {
                                Json_file->references += std::to_string(i+1) + ". " + std::string(json_data[1]["cna"]["references"][i]["url"]) + '\n'; 
                            }
                        }
                    }
                }
                else { 
                    Json_file->cveid = json_data["cveMetadata"]["cveId"];
                    Json_file->state = json_data["cveMetadata"]["state"];
                    if (Json_file->state == "PUBLISHED") {
                        
                        Json_file->description = json_data["containers"]["cna"]["descriptions"][0]["value"];
                        
                        if (!json_data["containers"]["cna"]["affected"][0]["product"].is_null()) {
                            if (std::string(json_data["containers"]["cna"]["affected"][0]["product"]) != "n/a") {
                                Json_file->affected += '\n';
                                for (size_t j = 0; j < json_data["containers"]["cna"]["affected"].size(); ++j) {
                                    
                                    Json_file->affected += std::to_string(j+1) + ". " + std::string(json_data["containers"]["cna"]["affected"][j]["product"]);
                                    
                                    if (!(json_data["containers"]["cna"]["affected"][j]["versions"][0]["lessThanOrEqual"].is_null())) {
                                        Json_file->affected += " <= " + std::string(json_data["containers"]["cna"]["affected"][j]["versions"][0]["lessThanOrEqual"]);
                                    }
                                    else if (!(json_data["containers"]["cna"]["affected"][j]["versions"][0]["lessThan"].is_null())) {
                                        Json_file->affected += " < " + std::string(json_data["containers"]["cna"]["affected"][j]["versions"][0]["lessThan"]);
                                    }
                                    else if (!(json_data["containers"]["cna"]["affected"][j]["versions"][0]["version"].is_null())) {
                                        Json_file->affected += " = " + std::string(json_data["containers"]["cna"]["affected"][j]["versions"][0]["version"]);
                                    }
                                    if (j+1 != json_data["containers"]["cna"]["affected"].size()) {
                                        Json_file->affected += '\n';
                                    }
                                }
                            }
                        }

                        if (!json_data["containers"]["cna"]["metrics"].is_null()) {
                            if (!json_data["containers"]["cna"]["metrics"][0]["cvssV4_0"].is_null()) {
                                if (!json_data["containers"]["cna"]["metrics"][0]["cvssV4_0"]["baseScore"].is_null() && !json_data["containers"]["cna"]["metrics"][0]["cvssV4_0"]["baseSeverity"].is_null()) {
                                    Json_file->severity = float_to_string(json_data["containers"]["cna"]["metrics"][0]["cvssV4_0"]["baseScore"].get<double>()) + " " + std::string(json_data["containers"]["cna"]["metrics"][0]["cvssV4_0"]["baseSeverity"]) + " (CVSS V4_0)"; 
                                }
                            }
                            else if (!json_data["containers"]["cna"]["metrics"][0]["cvssV3_1"].is_null()) {
                                if (!json_data["containers"]["cna"]["metrics"][0]["cvssV3_1"]["baseScore"].is_null() && !json_data["containers"]["cna"]["metrics"][0]["cvssV3_1"]["baseSeverity"].is_null()) {
                                    Json_file->severity = float_to_string(json_data["containers"]["cna"]["metrics"][0]["cvssV3_1"]["baseScore"].get<double>()) + " " + std::string(json_data["containers"]["cna"]["metrics"][0]["cvssV3_1"]["baseSeverity"]) + " (CVSS V3_1)"; 
                                }
                            }
                            else if (!json_data["containers"]["cna"]["metrics"][0]["cvssV3_0"].is_null()) {
                                if (!json_data["containers"]["cna"]["metrics"][0]["cvssV3_0"]["baseScore"].is_null() && !json_data["containers"]["cna"]["metrics"][0]["cvssV3_0"]["baseSeverity"].is_null()) {
                                    Json_file->severity = float_to_string(json_data["containers"]["cna"]["metrics"][0]["cvssV3_0"]["baseScore"].get<double>()) + " " + std::string(json_data["containers"]["cna"]["metrics"][0]["cvssV3_0"]["baseSeverity"]) + " (CVSS V3_0)"; 
                                }
                            }
                            else if (!json_data["containers"]["cna"]["metrics"][0]["cvssV2_0"].is_null()) {
                                if (!json_data["containers"]["cna"]["metrics"][0]["cvssV2_0"]["baseScore"].is_null()) {
                                    Json_file->severity = float_to_string(json_data["containers"]["cna"]["metrics"][0]["cvssV2_0"]["baseScore"].get<double>()) + " (CVSS V2_0)";
                                }
                            }
                        }

                        if (!json_data["containers"]["cna"]["x_legacyV4Record"]["impact"].is_null()) {
                            if (!json_data["containers"]["cna"]["x_legacyV4Record"]["impact"].is_array()) {
                                if (!json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"].is_null()) {
                                    if (json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"].is_array()) {
                                        if (json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0].is_array()) {
                                            if (!json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0][0]["baseScore"].is_null() && !json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0][0]["baseSeverity"].is_null()) {
                                                Json_file->impact = (json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0][0]["baseScore"].dump()) + ' ' + std::string(json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0][0]["baseSeverity"]);    
                                            }
                                            else if (!json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0][0]["vectorString"].is_null()) {
                                                Json_file->impact = std::string(json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0][0]["vectorString"]);
                                            }
                                        }
                                        else {
                                            if (!json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0]["baseScore"].is_null() && !json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0]["baseSeverity"].is_null()) {
                                                Json_file->impact = (json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0]["baseScore"].dump()) + ' ' + std::string(json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0]["baseSeverity"]);    
                                            }
                                            else if (!json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0]["vectorString"].is_null()) {
                                                Json_file->impact = std::string(json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"][0]["vectorString"]);
                                            }
                                        }
                                    }
                                    else {
                                        if (!json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"]["baseScore"].is_null() && !json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"]["baseSeverity"].is_null()) {
                                            Json_file->impact = (json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"]["baseScore"].dump()) + ' ' + std::string(json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"]["baseSeverity"]);    
                                        }
                                        else if (!json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"]["vectorString"].is_null()) {
                                            Json_file->impact = std::string(json_data["containers"]["cna"]["x_legacyV4Record"]["impact"]["cvss"]["vectorString"]);
                                        }
                                    }
                                }
                            }
                        }

                        if (!json_data["containers"]["cna"]["references"].is_null()) {
                            Json_file->references += '\n';
                            for (size_t i = 0; i < json_data["containers"]["cna"]["references"].size(); ++i) {
                                Json_file->references += std::to_string(i+1) + ". " + std::string(json_data["containers"]["cna"]["references"][i]["url"]) + '\n';
                            }
                        }
                    }
                }
                if (!Json_file->description.empty()) {
                    if (Json_file->description.find(argv[2]) != std::string::npos) {
                        std::cout << "Status: " << Json_file->state << '\n';
                        std::cout << "CVE id: " << Json_file->cveid << '\n';
                        std::cout << "Impact: " << Json_file->impact << '\n';
                        std::cout << "Severity: " << Json_file->severity << '\n';
                        std::cout << "Affected: " << Json_file->affected << '\n';
                        std::cout << "Raw data: " << de.path().string() << '\n';
                        std::cout << "References: " << Json_file->references;
                        std::cout << "Description: " << Json_file->description << "\n\n\n\n\n";
                    }
                }
                delete Json_file;
                reader.close();
            }
        }
    }
    else {
        display_help();
        return 1;
    }
    return 0;

}
