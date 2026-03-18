<?php
/**
 * Database: PDO wrapper for MySQL interactions.
 */
class Database
{
    /** @var PDO */
    private $pdo;

    /**
     * @param array $config Database config array with keys: host, name, user, pass, charset
     * @throws PDOException
     */
    public function __construct(array $config)
    {
        $dsn = sprintf(
            'mysql:host=%s;dbname=%s;charset=%s',
            $config['host'],
            $config['name'],
            $config['charset']
        );

        $this->pdo = new PDO($dsn, $config['user'], $config['pass'], [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]);
    }

    /**
     * Execute a prepared statement (INSERT, UPDATE, DELETE).
     *
     * @param string $sql    SQL with named placeholders
     * @param array  $params Associative array of placeholder => value
     */
    public function execute(string $sql, array $params = []): void
    {
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);
    }

    /**
     * Return the underlying PDO connection.
     */
    public function getConnection(): PDO
    {
        return $this->pdo;
    }
}
