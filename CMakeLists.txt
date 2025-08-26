cmake_minimum_required(VERSION 3.27)
project(VerifiableProvenance)

set(CMAKE_CXX_STANDARD 17)
link_libraries(crypto)
add_executable(VerifiableCausality main.cpp MBNT.cpp utils.cpp VersionProv.cpp Log.cpp SSdataset_handler.cpp TCdataset_handler.cpp dataset_handler.cpp experiment_MBNT.cpp)
