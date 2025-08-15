// Package encrypt
// @Link  https://github.com/bufanyun/hotgo
// @Copyright  Copyright (c) 2023 HotGo CLI
// @Author  Ms <133814250@qq.com>
// @License  https://github.com/bufanyun/hotgo/blob/master/LICENSE
package encrypt

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"io"

	"golang.org/x/crypto/bcrypt"
)

// Md5ToString 生成md5
func Md5ToString(str string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(str)))
}

// Md5 生成md5
func Md5(b []byte) string {
	return fmt.Sprintf("%x", md5.Sum(b))
}

func Hash32(b []byte) uint32 {
	h := fnv.New32a()
	h.Write(b)
	return h.Sum32()
}

// GenerateSalt 生成一个指定长度的随机盐值
func GenerateSalt(size int) (string, error) {
	saltBytes := make([]byte, size)
	// 使用 crypto/rand 生成高质量的随机字节
	if _, err := io.ReadFull(rand.Reader, saltBytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(saltBytes), nil
}

// HashPasswordWithSalt 对密码进行加盐 MD5 哈希
// 返回哈希后的密码摘要和所使用的盐
func Md5HashPasswordWithSalt(password string) (string, string, error) {
	// 1. 生成一个随机的 Salt (例如 16 字节)
	salt, err := GenerateSalt(16)
	if err != nil {
		return "", "", err
	}

	// 2. 将密码和 Salt 拼接 (可以自行决定拼接顺序，但验证时必须一致)
	// 常见方式：password + salt 或者 salt + password
	passwordWithSalt := password + salt

	// 3. 进行 MD5 哈希
	hasher := md5.New()
	hasher.Write([]byte(passwordWithSalt))
	hashedPassword := hex.EncodeToString(hasher.Sum(nil))

	// 4. 返回哈希值和 Salt
	return hashedPassword, salt, nil
}

// VerifyPassword 验证密码是否正确
func VerifyMd5HashPasswordWithSalt(password, storedHash, salt string) bool {
	// 1. 使用相同的拼接方式组合密码和盐
	passwordWithSalt := password + salt

	// 2. 计算哈希值
	hasher := md5.New()
	hasher.Write([]byte(passwordWithSalt))
	currentHash := hex.EncodeToString(hasher.Sum(nil))

	// 3. 比较哈希值是否相等
	return currentHash == storedHash
}

// BcryptHashPassword 使用 bcrypt 对密码进行哈希
func BcryptHashPassword(password string) (string, error) {
	// bcrypt.GenerateFromPassword 会自动生成 salt
	// bcrypt.DefaultCost 是默认的工作因子 (cost)，可以根据需要调整
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// BcryptCheckPasswordHash 验证密码和哈希值是否匹配
func BcryptCheckPasswordHash(password, hash string) bool {
	// CompareHashAndPassword 会从 hash 中提取 salt 并进行比较
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
