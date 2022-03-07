import copy

from collections import UserList
from typing import Dict, Any, Sequence, Optional, List

from sc_api_tools.data_models.algorithms import Algorithm
from sc_api_tools.data_models.enums import Domain, TaskType


class AlgorithmList(UserList):
    """
    A list containing SC supported algorithms
    """

    def __init__(self, data: Optional[Sequence[Algorithm]] = None):
        self.data: List[Algorithm] = []
        if data is not None:
            super().__init__(list(data))

    @staticmethod
    def from_rest(rest_input: Dict[str, Any]) -> 'AlgorithmList':
        """
        Creates an AlgorithmList from the response of the /supported_algorithms REST
        endpoint in SC

        :param rest_input: Dictionary retrieved from the /supported_algorithms REST
            endpoint
        :return: AlgorithmList holding the information related to the supported
            algorithms in SC
        """
        algorithm_list = AlgorithmList([])
        algo_rest_list = copy.deepcopy(rest_input["items"])
        for algorithm_dict in algo_rest_list:
            algorithm_list.append(Algorithm(**algorithm_dict))
        return algorithm_list

    def get_by_model_template(self, model_template_id: str) -> Algorithm:
        """
        Retrieves an algorithm from the list by its model_template_id

        :param model_template_id: Name of the model template to get the Algorithm
            information for
        :return: Algorithm holding the algorithm details
        """
        for algo in self.data:
            if algo.model_template_id == model_template_id:
                return algo
        raise ValueError(
            f"Algorithm for model template {model_template_id} was not found in the "
            f"list of supported algorithms."
        )

    def get_by_task_type(self, task_type: TaskType) -> 'AlgorithmList':
        """
        Returns a list of supported algorithms for a particular task type

        :param task_type: TaskType to get the supported algorithms for
        :return: List of supported algorithms for the task type
        """
        return AlgorithmList(
            [
                algo for algo in self.data
                if algo.task_type == task_type
            ]
        )

    @property
    def summary(self) -> str:
        """
        Returns a string that gives a very brief summary of the algorithm list.

        :return: String holding a brief summary of the list of algorithms
        """
        summary_str = "Algorithms:\n"
        for algorithm in self.data:
            summary_str += f"  Name: {algorithm.algorithm_name}\n" \
                           f"    Task type: {algorithm.task_type}\n" \
                           f"    Model size: {algorithm.model_size}\n" \
                           f"    Gigaflops: {algorithm.gigaflops}\n\n"
        return summary_str

    def get_by_name(self, name: str) -> Algorithm:
        """
        Retrieves an algorithm from the list by its algorithm_name

        :param name: Name of the Algorithm to get
        :return: Algorithm holding the algorithm details
        """
        for algo in self.data:
            if algo.algorithm_name == name:
                return algo
        raise ValueError(
            f"Algorithm named {name} was not found in the "
            f"list of supported algorithms."
        )