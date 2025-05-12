#include <iostream>
#include <fstream>
#include <vector>
#include <memory>
#include <string>
#include <cstring>

#include "pvm_bindings/pvm_bindings.h"

struct PVMConfigWrapper {
    PVMConfig* config;
    
    PVMConfigWrapper(uint32_t memory_size) {
        config = pvm_config_create(memory_size);
        if (!config) {
            throw std::runtime_error("Failed to create PVM config");
        }
    }
    
    ~PVMConfigWrapper() {
        pvm_config_free(config);
    }

    void setAllowDynamicPaging(bool allow) {
        pvm_config_set_allow_dynamic_paging(config, allow);
    }

    void setWorkerCount(uint32_t count) {
        pvm_config_set_worker_count(config, count);
    }

    void setBackend(PVMBackend backend) {
        pvm_config_set_backend(config, backend);
    }

    void setSandbox(PVMSandbox sandbox) {
        pvm_config_set_sandbox(config, sandbox);
    }
};

struct PVMEngineWrapper {
    PVMEngine* engine;
    
    PVMEngineWrapper(const PVMConfig* config) {
        engine = pvm_engine_new(config);
        if (!engine) {
            throw std::runtime_error("Failed to create PVM engine");
        }
    }
    
    ~PVMEngineWrapper() {
        pvm_engine_free(engine);
    }
};

struct PVMModuleWrapper {
    PVMModule* module;
    
    PVMModuleWrapper(const PVMEngine* engine, const uint8_t* blob, size_t size) {
        module = pvm_module_from_blob(engine, blob, size);
        if (!module) {
            throw std::runtime_error("Failed to create PVM module");
        }
    }
    
    ~PVMModuleWrapper() {
        pvm_module_free(module);
    }
};

struct PVMLinkerWrapper {
    PVMLinker* linker;
    
    PVMLinkerWrapper() {
        linker = pvm_linker_new();
        if (!linker) {
            throw std::runtime_error("Failed to create PVM linker");
        }
    }
    
    ~PVMLinkerWrapper() {
        pvm_linker_free(linker);
    }
};

struct PVMInstanceWrapper {
    PVMInstance* instance;
    
    PVMInstanceWrapper(const PVMModule* module, const PVMLinker* linker) {
        instance = pvm_instance_new_with_linker(module, linker);
        if (!instance) {
            throw std::runtime_error("Failed to create PVM instance");
        }
    }
    
    ~PVMInstanceWrapper() {
        pvm_instance_free(instance);
    }
};

std::vector<uint8_t> loadBinaryFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) {
        throw std::runtime_error("Failed to open file: " + filename);
    }
    
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<uint8_t> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        throw std::runtime_error("Failed to read file: " + filename);
    }
    
    return buffer;
}

extern "C" uint32_t example_external_function(
    uint32_t import_id,
    const uint32_t* args,
    uint32_t args_count,
    void* user_data
) {
    std::cout << "External function called with import_id: " << import_id << std::endl;
    std::cout << "Arguments: ";
    for (uint32_t i = 0; i < args_count; ++i) {
        std::cout << args[i] << " ";
    }
    std::cout << std::endl;
    
    uint32_t sum = 0;
    for (uint32_t i = 0; i < args_count; ++i) {
        sum += args[i];
    }
    return sum;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <pvm-binary-file>" << std::endl;
        return 1;
    }
    
    try {
        std::vector<uint8_t> binary = loadBinaryFile(argv[1]);
        std::cout << "Loaded PVM binary: " << argv[1] << " (" << binary.size() << " bytes)" << std::endl;
        
        PVMConfigWrapper config(1024 * 1024);
        
        config.setAllowDynamicPaging(true);
        config.setWorkerCount(1);
        config.setBackend(PVMBackend::Compiler);
        config.setSandbox(PVMSandbox::Linux);
        
        PVMEngineWrapper engine(config.config);
        PVMModuleWrapper module(engine.engine, binary.data(), binary.size());
        
        PVMLinkerWrapper linker;
        const char* external_func_name = "example_function";
        if (!pvm_linker_define_function(
            linker.linker,
            reinterpret_cast<const uint8_t*>(external_func_name),
            strlen(external_func_name),
            example_external_function,
            nullptr
        )) {
            throw std::runtime_error("Failed to define external function");
        }
        
        PVMInstanceWrapper instance(module.module, linker.linker);
        
        uint32_t result;
        const char* func_name = "add_numbers";
        uint32_t args[] = {5, 7};
        
        if (!pvm_instance_call_function(
            instance.instance,
            reinterpret_cast<const uint8_t*>(func_name),
            strlen(func_name),
            args,
            2,
            &result
        )) {
            throw std::runtime_error("Failed to call function");
        }
        
        std::cout << "Function call result: " << result << std::endl;
        
        PVMInterruptKind interrupt;
        bool success = pvm_instance_run(instance.instance, &interrupt);
        
        if (!success) {
            throw std::runtime_error("VM execution failed");
        }
        
        if (interrupt.tag == PVMInterruptKind_Finished) {
            std::cout << "Program executed successfully" << std::endl;
        } else if (interrupt.tag == PVMInterruptKind_Ecalli) {
            uint32_t import_id = interrupt.ecalli.value;
            std::cout << "External call requested, import ID: " << import_id << std::endl;
        } else {
            std::cout << "VM interrupted with: " << interrupt.tag << std::endl;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
} 