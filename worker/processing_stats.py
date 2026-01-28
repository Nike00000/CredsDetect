from typing import List, Optional
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime 

class FileStatus(Enum):
    WAIT = 'Waiting'
    ACTIVE = 'Active'
    ERROR = 'Error'
    DONE = 'Done'

@dataclass
class FileStats:
    filename: str = ""
    status:  FileStatus = FileStatus.WAIT
    start_time: Optional[float] = None
    end_time: Optional[float] = None

@dataclass
class ProcessingStats:
    """Общая статистика обработки"""
    status = "Active"
    total_files: 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

    def __init__(self, input_files: List[str]):
        self.file_stats: List[FileStats] = []
        for input_file in input_files:
            stat = FileStats(input_file, FileStatus.WAIT)
            self.file_stats.append(stat)
        self.total_files = len(input_files)

    def update_status(self, status: FileStatus, filename: str):
        for file_stat in self.file_stats:
            if file_stat.filename == filename:
                file_stat.status = status
                if status is FileStatus.ACTIVE:
                    file_stat.start_time = datetime.now()
                elif status is FileStatus.DONE:
                    file_stat.end_time = datetime.now()

    def get_files_with_status(self, status: FileStatus) -> List[FileStats]:
        result: List[FileStats] = []
        for file_stat in self.file_stats:
            if file_stat.status is status:
                result.append(file_stat)
        return result
    
    def count_files_with_status(self, status: FileStatus) -> int:
        return len(self.get_files_with_status(status))