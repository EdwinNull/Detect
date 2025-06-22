from app.services.classifier import SecurityClassifier

def main():
    print("开始重新训练模型...")
    clf = SecurityClassifier()
    clf.retrain()
    print("模型重新训练完成")

if __name__ == "__main__":
    main() 