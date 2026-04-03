CREATE DATABASE ShoppingDB;
GO
USE ShoppingDB;

CREATE TABLE Products(
    Id INT PRIMARY KEY IDENTITY,
    Name NVARCHAR(100),
    Price DECIMAL(10,2),
    Stock INT
);

CREATE TABLE Orders(
    Id INT PRIMARY KEY IDENTITY,
    ProductId INT,
    Qty INT,
    OrderDate DATETIME DEFAULT GETDATE()
);

INSERT INTO Products(Name, Price, Stock)
VALUES
('Laptop', 50000, 10),
('Mouse', 500, 50),
('Keyboard', 1000, 25);
