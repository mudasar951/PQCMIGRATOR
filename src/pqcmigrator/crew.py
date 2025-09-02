from crewai import Agent, Crew, Process, Task
from crewai.project import CrewBase, agent, crew, task
from crewai.agents.agent_builder.base_agent import BaseAgent
from typing import List
from dotenv import load_dotenv

from pqcmigrator.tools.scanner_agent.TLS_tool import TLSScannerTool
from pqcmigrator.tools.scanner_agent.SSH_tool import SSHScannerTool
from pqcmigrator.tools.scanner_agent.CODE_tool import CodeScannerTool
from pqcmigrator.tools.scanner_agent.YARA_tool import YARAScannerTool
# from pqcmigrator.tools.scanner_agent.RiskAnalyzerTool import RiskAnalyzerTool
# from pqcmigrator.tools.scanner_agent.PlannerTool import PlannerTool
# from pqcmigrator.tools.scanner_agent.MigratorTool import MigratorTool
# from pqcmigrator.tools.scanner_agent.RollbackTool import RollbackTool



load_dotenv()





@CrewBase
class PQCMigrator():
    """PQCMigrator crew"""

    agents: List[BaseAgent]
    tasks: List[Task]
    

    def __init__(self):
        super().__init__()

    # Tool functions marked with is_tool attribute
    def tls_scanner_tool(self):
        return TLSScannerTool()
    tls_scanner_tool.is_tool = True

    def ssh_scanner_tool(self):
        return SSHScannerTool()
    ssh_scanner_tool.is_tool = True

    def code_scanner_tool(self):
        return CodeScannerTool()
    code_scanner_tool.is_tool = True

    def yara_scanner_tool(self):
        return YARAScannerTool()
    yara_scanner_tool.is_tool = True

    # def risk_analyzer_tool(self):
    #     return RiskAnalyzerTool()
    # risk_analyzer_tool.is_tool = True

    # def planner_tool(self):
    #     return PlannerTool()
    # planner_tool.is_tool = True

    # def migrator_tool(self):
    #     return MigratorTool()
    # migrator_tool.is_tool = True

    # def rollback_tool(self):
    #     return RollbackTool()
    # rollback_tool.is_tool = True

    # Agents
    @agent
    def scanner(self) -> Agent:
        return Agent(
            config=self.agents_config['scanner'],  # matches agents.yaml
            verbose=True
        )

    # @agent
    # def risk_analyzer(self) -> Agent:
    #     return Agent(
    #         config=self.agents_config['risk_analyzer'],
    #         verbose=True
    #     )

    # @agent
    # def planner(self) -> Agent:
    #     return Agent(
    #         config=self.agents_config['planner'],
    #         verbose=True
    #     )

    # @agent
    # def migrator(self) -> Agent:
    #     return Agent(
    #         config=self.agents_config['migrator'],
    #         verbose=True
    #     )

    # @agent
    # def rollback(self) -> Agent:
    #     return Agent(
    #         config=self.agents_config['rollback'],
    #         verbose=True
    #     )

    # Tasks
    @task
    def scanner_task(self) -> Task:
        return Task(
            config=self.tasks_config['scanner_task'],
        )

    # @task
    # def risk_analyzer_task(self) -> Task:
    #     return Task(
    #         config=self.tasks_config['risk_analyzer_task'],
    #     )

    # @task
    # def planner_task(self) -> Task:
    #     return Task(
    #         config=self.tasks_config['planner_task'],
    #     )

    # @task
    # def migrator_task(self) -> Task:
    #     return Task(
    #         config=self.tasks_config['migrator_task'],
    #     )

    # @task
    # def rollback_task(self) -> Task:
    #     return Task(
    #         config=self.tasks_config['rollback_task'],
    #     )

    # Crew
    @crew
    def crew(self) -> Crew:
        """Creates the PQCMigrator crew"""
        return Crew(
            agents=self.agents,
            tasks=self.tasks,
            process=Process.sequential,
            verbose=True
        )
