from rich.table import Table
from rich.layout import Layout
from rich.panel import Panel
from rich.align import Align
from rich import box
from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn, TimeRemainingColumn, TimeElapsedColumn
from worker.processing_stats import FileStatus, ProcessingStats
from containers.results_container import ResultsContainer
from datetime import datetime, timedelta
from dto.enums import NTLMResponseEnum, KerberosEtypeEnum, UserPassProtocolEnum
from datetime import datetime 

def create_dashboard(processing_stats: ProcessingStats, results: ResultsContainer) -> Layout:
    layout = Layout()
    
    layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main"),
            Layout(name="footer", size=3)
        )

    layout["header"].update(
                Panel(
                        Align.center(
                            "[bold dim]CredsDetect Dashboard[/bold dim]\n",
                            vertical="middle"
                        ),
                        border_style="dim"
                    )
                )

    layout["main"].split_row(
        Layout(name="left"),
        Layout(name="right")
    )
    

    layout["right"].split_column(
        Layout(create_stats_table(processing_stats), name="stats", size=6),
        Layout(create_user_pass_table(results=results), name="user_pass", size=12)
    )

    layout["left"].split_column(
        Layout(create_ntlm_table(results=results), name="ntlm", size=7),
        Layout(create_kerberos_table(results=results), name="kerberos", size=14)
    )
    if processing_stats.end_time == None:
        delta_datetime = datetime.now() - processing_stats.start_time
    else:
        delta_datetime = processing_stats.end_time - processing_stats.start_time

    layout["footer"].update(
        Panel.fit(
            f"[dim]Status:[/dim] [green]{processing_stats.status}[/green] [dim] | "
            f"Total time:[/dim] {delta_datetime} [dim] | "
            f"Developed by:[/dim] @Nike417",
            border_style="dim"
        )
    )

    return layout

def create_progress():
    progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            TextColumn("•"),
            TimeRemainingColumn(),
        )

def create_stats_table(processing_stats: ProcessingStats) -> Table:
    table = Table(title='Task statistics',
                  show_header=True,
                  header_style="dim",
                  box=box.ROUNDED,
                  expand=True)
    table.add_column("success", justify="center")
    table.add_column("errors",  justify="center")
    table.add_column("total", justify="center")
    table.add_column("time/file", justify="right")
    table.add_column("timefile/process", justify="right")
    table.add_column("percent", justify="right", style='cyan')
    done_files = processing_stats.get_files_with_status(FileStatus.DONE)
    count_done_files = len(done_files)
    all_time = timedelta(0)
    for file in done_files:
        all_time += file.end_time - file.start_time
    if count_done_files > 0:
        average_time = f"{(all_time / count_done_files).total_seconds():.2f}"
    else:
        average_time = '-'

    count_error_files = processing_stats.count_files_with_status(FileStatus.ERROR)
    common_time = datetime.now() - processing_stats.start_time
    common_files = count_done_files + count_error_files
    if common_files == 0:
        common_by_file = '-'
    else:
        common_by_file = f"{(common_time / common_files).total_seconds():.2f}"
    

    percentage = f"{(count_done_files + count_error_files)* 100 / processing_stats.total_files:.2f}%"
    table.add_row(str(count_done_files),
                    str(count_error_files),
                    str(processing_stats.total_files),
                    average_time,
                    common_by_file,
                    percentage)
    return table

def create_ntlm_table(results: ResultsContainer) -> Table:
    table = Table(title='NetNTLM statistics',
                  show_header=True,
                  header_style="dim",
                  box=box.ROUNDED,
                  expand=True)
    table.add_column("response", justify="center")
    table.add_column("version", justify="center")
    table.add_column("all", justify="center")
    table.add_column("user", justify="center")
    table.add_column("unique user", justify="center")

    for response_type in NTLMResponseEnum:
        table.add_row('NT',
                      str(response_type.value),
                      str(len(results.ntlm_container.responses[response_type].all)),
                      str(len(results.ntlm_container.responses[response_type].users)),
                      str(len(results.ntlm_container.responses[response_type].unique)))
    return table

def create_user_pass_table(results: ResultsContainer) -> Table:
    table = Table(title='Clear text statistics',
                  show_header=True,
                  header_style="dim",
                  box=box.ROUNDED,
                  expand=True)
    table.add_column("protocol", justify="center")
    table.add_column("user", justify="center")
    table.add_column("unique user", justify="center")
    table.add_column("pass", justify="center")
    table.add_column("unique pass", justify="center")



    for user_pass_protocol in UserPassProtocolEnum:
        table.add_row(str(user_pass_protocol.value),
                      str(len(results.user_pass_container.usernames[user_pass_protocol].all)),
                      str(len(results.user_pass_container.usernames[user_pass_protocol].unique)),
                      str(len(results.user_pass_container.passwords[user_pass_protocol].all)),
                      str(len(results.user_pass_container.passwords[user_pass_protocol].unique)),)
    return table

def create_kerberos_table(results: ResultsContainer) -> Table:
    table = Table(title='Kerberos statistics',
                  show_header=True,
                  header_style="dim",
                  box=box.ROUNDED,
                  expand=True)
    table.add_column("type", justify="center")
    table.add_column("etype", justify="center")
    table.add_column("all", justify="center")
    table.add_column("user", justify="center")
    table.add_column("unique user", justify="center")

    for etype_type in KerberosEtypeEnum:
        table.add_row('ASREQ',
                      str(etype_type.value),
                      str(len(results.kerberos_container.asreq[etype_type].all)),
                      str(len(results.kerberos_container.asreq[etype_type].users)),
                      str(len(results.kerberos_container.asreq[etype_type].unique)))
        table.add_row('ASREP',
                      str(etype_type.value),
                      str(len(results.kerberos_container.asrep[etype_type].all)),
                      str(len(results.kerberos_container.asrep[etype_type].users)),
                      str(len(results.kerberos_container.asrep[etype_type].unique)))
        table.add_row('TGSREP',
                      str(etype_type.value),
                      str(len(results.kerberos_container.tgsrep[etype_type].all)),
                      str(len(results.kerberos_container.tgsrep[etype_type].users)),
                      str(len(results.kerberos_container.tgsrep[etype_type].unique)))

    return table