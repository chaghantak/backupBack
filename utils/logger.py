import logging


class Logger:
    @staticmethod
    def get_level():
        return 'INFO'

    @staticmethod
    def get_filename():
        return './logs/logs.log'

    @staticmethod
    def get_format():
        return '%(asctime)s.%(msecs)03d %(levelname)5s %(name)s - %(message)s'

    @staticmethod
    def get_date_format():
        return '%Y-%m-%dT%H:%M:%S'

    @staticmethod
    def get_logger(name):
        logger = logging.getLogger(name)
        logger.setLevel(Logger.get_level())

        formatter = logging.Formatter(
            Logger.get_format(),
            Logger.get_date_format()
        )

        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)

        file_handler = logging.FileHandler(Logger.get_filename())
        file_handler.setFormatter(formatter)
        logger.addHandler(hdlr=file_handler)

        return logger
