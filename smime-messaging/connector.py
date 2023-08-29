""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from .operations import operations, check_health
from connectors.core.connector import Connector, get_logger, ConnectorError

logger = get_logger('smime-messaging')


class SMIME(Connector):
    def execute(self, config, operation, params, *args, **kwargs):
        try:
            action = operations.get(operation)
            logger.info('Executing action {}'.format(action))
            return action(config, params, *args, **kwargs)
        except Exception as err:
            logger.exception("An exception occurred [{}]".format(err))
            raise ConnectorError("An exception occurred [{}]".format(err))

    def check_health(self, config):
        logger.info('starting health check')
        check_health(config)
        logger.info('completed health check no errors')
