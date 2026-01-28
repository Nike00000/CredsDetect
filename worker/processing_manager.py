from rich.console import Console
from rich.live import Live
from queue import Empty
from typing import List, Iterable
from containers.results_container import ResultsContainer
from worker.processing_stats import ProcessingStats, FileStatus
from worker.dashboard_manager import create_dashboard
from datetime import datetime
from dto.base_data import BaseData
import time
import multiprocessing
import json
from dto.kerberos_data import AsreqKerberos, AsrepKerberos, TgsrepKerberos
from dto.net_ntlm_data import ChallengeNetNTLM, ResponseNetNTLM
from dto.user_pass_data import UserPassData

class ProcessingManager:

    data_objects = [ChallengeNetNTLM,
                ResponseNetNTLM,
                AsreqKerberos,
                AsrepKerberos,
                TgsrepKerberos,
                UserPassData]

    def __init__(self, count_processes: int, input_files: List[str], 
                 filter_protocols: List[str], tshark_path: str, current_result: bool):
        self.console = Console()
        self.count_processes = count_processes
        self.input_files = input_files
        self.filter_protocols = filter_protocols
        self.tshark_path = tshark_path
        self.current_result = current_result
        self.processed_files = 0
        self.processing_stats = ProcessingStats(input_files)
        self.results: ResultsContainer = ResultsContainer()

    def _validate_parameters(self) -> None:
        cpu_count = multiprocessing.cpu_count()
        if self.count_processes < 1 or self.count_processes > cpu_count:
            self.console.print(f"[yellow]Bad number of processes {self.count_processes}. Set default value {cpu_count}[/yellow]")

    def process_files(self, process_file_func) -> List:
        self.processing_stats.start_time = datetime.now()
        self._validate_parameters()
        self.console.print(f"{self.count_processes} threads have been selected for file processing")
        
        with multiprocessing.Manager() as manager:
            shared_queue = manager.Queue()
            return self._run_processing_pipeline(shared_queue, process_file_func)
        
    def _run_processing_pipeline(self, shared_queue: multiprocessing.Queue, process_file_func) -> List:
        pool = None
        try:
            pool, tasks = self._create_process_pool(shared_queue, process_file_func)
            self._monitor_processing(shared_queue, tasks)
        except Exception as e:
            self.console.print(f"[red][!] Critical error: {e}[/red]")
        finally:
            self._cleanup_pool(pool)
    
    def _create_process_pool(self, shared_queue: multiprocessing.Queue, process_file_func):
        pool = multiprocessing.Pool(processes=self.count_processes)
        tasks = []
        for file_path in self.input_files:
            task = pool.apply_async(
                process_file_func,
                args=(file_path, shared_queue, self.filter_protocols, self.tshark_path),
                error_callback=lambda e, fp=file_path: 
                self.console.print(f"[red][!] Error processing {fp}: {e}[/red]")
            )
            tasks.append(task)

        return pool, tasks
    

    def _monitor_processing(self, shared_queue: multiprocessing.Queue, tasks) -> None:
        """Мониторит процесс обработки файлов"""
        with Live(create_dashboard(self.processing_stats, self.results), refresh_per_second=4, console=self.console) as live:
            last_update = datetime.now()
            update_interval = 0.5
            
            while True:
                current_time = datetime.now()

                if (current_time - last_update).total_seconds() >= update_interval:
                    live.update(create_dashboard(self.processing_stats, self.results))
                    last_update = current_time

                all_tasks_done = all(task.ready() for task in tasks)
                queue_empty = shared_queue.empty()

                if all_tasks_done and queue_empty:
                    time.sleep(0.1)
                    if shared_queue.empty():
                        self.processing_stats.status = "Done"
                        self.processing_stats.end_time = datetime.now()
                        live.update(create_dashboard(self.processing_stats, self.results))
                        break
                
                try:
                    file_path, status, current_results = shared_queue.get_nowait()
                    self._process_queue_message(file_path, status, current_results)
                except Empty:
                    time.sleep(0.01)
                except Exception as e:
                    self.console.print(f"[!] Error processing queue: {e}")
    
    def _cleanup_pool(self, pool) -> None:
        if pool is None:
            return
        self.console.print("[dim][*] Closing pool...[/dim]")
        pool.close()
        pool.terminate()
        pool.join()

    def _process_queue_message(self, file_path: str, status: FileStatus, current_results: str) -> None:
        self.processing_stats.update_status(status, filename=file_path)
        if status is FileStatus.ACTIVE:
            self._handle_file_started(file_path)
        elif status is FileStatus.DONE:
            self._handle_file_completed(file_path, current_results)
        elif status is FileStatus.ERROR:
            self._handle_file_failed(file_path, current_results)

    def _handle_file_started(self, file_path: str) -> None:
        pass
    
    def _handle_file_failed(self, file_path: str, error: str) -> None:
        self.console.print(f"[red][*] Error processing: {file_path} with error:/n {error}[/red]")

    def _handle_file_completed(self, file_path: str, 
                          str_results: str) -> None:
        results: List[BaseData] = []
        if self.current_result:
            for line in str_results.splitlines():
                try:
                    packet = json.loads(line)
                    if 'layers' in packet:
                        for data_object in self.data_objects:
                            try:
                                data = data_object(packet=packet, filename=file_path)
                                results.append(data)
                                break
                            except Exception as e:
                                pass
                except Exception as e:
                    continue

            for base_data in results:
                if base_data.is_user():
                    session = f"{base_data.src_ip}:{base_data.src_port} -> {base_data.dst_ip}:{base_data.dst_port}"
                    text = f"[dim][*] From the session {session} file {base_data.filename} protocol {base_data.protocol()} auth with {base_data.authentication_protocol} found data:[/dim]\n"
                    self.console.print(f"{text}{base_data.data()}", highlight=False)
            self.results.extend(list(results))
        


    