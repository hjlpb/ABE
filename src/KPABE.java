import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.stream.Collectors;

import static java.lang.Integer.valueOf;

public class KPABE {

    public static void setup(String pairingParametersFileName, int U, String pkFileName, String mskFileName) {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Element g = bp.getG1().newRandomElement().getImmutable();

        Properties mskProp = new Properties();
        Properties pkProp = new Properties();
        //属性表示为1，2，3，...，U
        //对每个属性i，选取一个随机数ti作为该属性对应的主密钥，并计算相应公钥g^ti
        for (int i = 1; i <= U; i++){
            Element t = bp.getZr().newRandomElement().getImmutable();
            Element T = g.powZn(t).getImmutable();
            mskProp.setProperty("t"+i, Base64.getEncoder().withoutPadding().encodeToString(t.toBytes()));
            pkProp.setProperty("T"+i, Base64.getEncoder().withoutPadding().encodeToString(T.toBytes()));
        }
        //另外选取一个随机数y，计算e(g,g)^y
        Element y = bp.getZr().newRandomElement().getImmutable();
        Element egg_y = bp.pairing(g, g).powZn(y).getImmutable();
        mskProp.setProperty("y", Base64.getEncoder().withoutPadding().encodeToString(y.toBytes()));
        pkProp.setProperty("egg_y", Base64.getEncoder().withoutPadding().encodeToString(egg_y.toBytes()));
        pkProp.setProperty("g", Base64.getEncoder().withoutPadding().encodeToString(g.toBytes()));

        storePropToFile(mskProp, mskFileName);
        storePropToFile(pkProp, pkFileName);
    }

    public static void keygen(String pairingParametersFileName, Node[] accessTree, String pkFileName, String mskFileName, String skFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Properties pkProp = loadPropFromFile(pkFileName);
        String gString = pkProp.getProperty("g");
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gString)).getImmutable();

        Properties mskProp = loadPropFromFile(mskFileName);
        String yString = mskProp.getProperty("y");
        Element y = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(yString)).getImmutable();

        //先设置根节点要共享的秘密值
        accessTree[0].secretShare = y;
        //进行共享，使得每个叶子节点获得响应的秘密分片
        nodeShare(accessTree, accessTree[0], bp);

        Properties skProp = new Properties();
        //计算每个属性对应的私钥g^(q/t)，q是多项式在该属性位置的值，t是属性对应的主密钥
        for (Node node : accessTree) {
            if (node.isLeaf()) {
                // 对于每个叶子结点，先获取对应的主秘钥组件t，然后计算秘钥组件。
                String tString = mskProp.getProperty("t"+node.att);
                Element t = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(tString)).getImmutable();
                Element q = node.secretShare;
                Element D = g.powZn(q.div(t)).getImmutable();
                skProp.setProperty("D"+node.att, Base64.getEncoder().withoutPadding().encodeToString(D.toBytes()));
            }
        }
        //将用户访问树也添加在私钥中
        //如何进行序列化和反序列化
//        skProp.setProperty("userAttList", Arrays.toString(accessTree));
        storePropToFile(skProp, skFileName);
    }

    public static void encrypt(String pairingParametersFileName, Element message, int[] messageAttList, String pkFileName, String ctFileName) {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Properties pkProp = loadPropFromFile(pkFileName);
        String eggString = pkProp.getProperty("egg_y");
        Element egg_y = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(eggString)).getImmutable();
        //计算密文组件 EP=Me(g,g)^(ys)
        Element s = bp.getZr().newRandomElement().getImmutable();
        Element EP = message.duplicate().mul(egg_y.powZn(s)).getImmutable();

        Properties ctProp = new Properties();
        //针对每个密文属性，计算密文组件 E=T^s
        for (int att : messageAttList) {
            String TString = pkProp.getProperty("T"+att);
            Element T = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(TString)).getImmutable();
            Element E = T.powZn(s).getImmutable();

            ctProp.setProperty("E"+att, Base64.getEncoder().withoutPadding().encodeToString(E.toBytes()));
        }
        ctProp.setProperty("EP", Base64.getEncoder().withoutPadding().encodeToString(EP.toBytes()));
        //密文属性列表也添加至密文中
        ctProp.setProperty("messageAttList", Arrays.toString(messageAttList));
        storePropToFile(ctProp, ctFileName);
    }

    public static Element decrypt(String pairingParametersFileName, Node[] accessTree, String pkFileName, String ctFileName, String skFileName) {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Properties pkProp = loadPropFromFile(pkFileName);

        Properties ctProp = loadPropFromFile(ctFileName);
        String messageAttListString = ctProp.getProperty("messageAttList");
        //恢复明文消息的属性列表 int[]类型
        int[] messageAttList = Arrays.stream(messageAttListString.substring(1, messageAttListString.length()-1).split(",")).map(String::trim).mapToInt(Integer::parseInt).toArray();

        Properties skProp = loadPropFromFile(skFileName);
        for (Node node : accessTree) {
            if (node.isLeaf()) {
                // 如果叶子节点的属性值属于属性列表，则将属性对应的密文组件和秘钥组件配对的结果作为秘密值
                if (Arrays.stream(messageAttList).boxed().collect(Collectors.toList()).contains(node.att)){
                    String EString = ctProp.getProperty("E"+node.att);
                    Element E = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(EString)).getImmutable();
                    String DString = skProp.getProperty("D"+node.att);
                    Element D = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(DString)).getImmutable();
                    // 这儿存在于密文属性列表中的叶子节点的秘密值是配对后的结果
                    node.secretShare = bp.pairing(E,D).getImmutable();
                }
            }
        }
        // 进行秘密恢复
        boolean treeOK = nodeRecover(accessTree, accessTree[0], messageAttList, bp);
        if (treeOK) {
            String EPString = ctProp.getProperty("EP");
            Element EP = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(EPString)).getImmutable();
            //恢复M=EP除以上述连乘结果
            Element res = EP.div(accessTree[0].secretShare);
            return res;
        }
        else{
            System.out.println("The access tree is not satisfied.");
            return  null;
        }
    }



    //d-1次多项式表示为q(x)=coef[0] + coef[1]*x^1 + coef[2]*x^2 + coef[d-1]*x^(d-1)
    //多项式的系数的数据类型为Zr Element，从而是的后续相关计算全部在Zr群上进行
    //通过随机选取coef参数，来构造d-1次多项式q(x)。约束条件为q(0)=s。
    public static Element[] randomP(int d, Element s, Pairing bp) {
        Element[] coef = new Element[d];
        coef[0] = s;
        for (int i = 1; i < d; i++){
            coef[i] = bp.getZr().newRandomElement().getImmutable();
        }
        return  coef;
    }
    //计算由coef为系数确定的多项式qx在点index处的值，注意多项式计算在群Zr上进行
    public static Element qx(Element index, Element[] coef, Pairing bp){
        Element res = coef[0].getImmutable();
        for (int i = 1; i < coef.length; i++){
            Element exp = bp.getZr().newElement(i).getImmutable();
            //index一定要使用duplicate复制使用，因为index在每一次循环中都要使用，如果不加duplicte，index的值会发生变化
            res = res.add(coef[i].mul(index.duplicate().powZn(exp)));
        }
        return res;
    }
    //拉格朗日因子计算 i是集合S中的某个元素，x是目标点的值
    public static Element lagrange(int i, int[] S, int x, Pairing bp) {
        Element res = bp.getZr().newOneElement().getImmutable();
        Element iElement = bp.getZr().newElement(i).getImmutable();
        Element xElement = bp.getZr().newElement(x).getImmutable();
        for (int j : S) {
            if (i != j) {
                //注意：在循环中重复使用的项一定要用duplicate复制出来使用
                //这儿xElement和iElement重复使用，但因为前面已经getImmutable所以可以不用duplicate
                Element numerator = xElement.sub(bp.getZr().newElement(j));
                Element denominator = iElement.sub(bp.getZr().newElement(j));
                res = res.mul(numerator.div(denominator));
            }
        }
        return res;
    }

    // 共享秘密
    // nodes是整颗树的所有节点，n是要分享秘密的节点
    public static void nodeShare(Node[] nodes, Node n, Pairing bp){
        // 如果是叶子节点，则不需要再分享
        if (!n.isLeaf()){
            // 如果不是叶子节点，则先生成一个随机多项式，多项式的常数项为当前节点的秘密值（这个值将被用于分享）
            // 多项式的次数，由节点的gate对应的threshold决定
            Element[] coef = randomP(n.gate[0], n.secretShare, bp);
            for (int j=0; j<n.children.length; j++ ){
                Node childNode = nodes[n.children[j]];
                // 对于每一个子节点，以子节点的索引为横坐标，计算子节点的多项式值（也就是其对应的秘密分片）
                childNode.secretShare = qx(bp.getZr().newElement(n.children[j]), coef, bp);
                // 递归，将该子节点的秘密继续共享下去
                nodeShare(nodes, childNode, bp);
            }
        }
    }

    // 恢复秘密
    public static boolean nodeRecover(Node[] nodes, Node n,  int[] atts, Pairing bp) {
        if (!n.isLeaf()) {
            // 对于内部节点，维护一个子节点索引列表，用于秘密恢复。
            List<Integer> validChildrenList = new ArrayList<Integer>();
            int[] validChildren;
            // 遍历每一个子节点
            for (int j=0; j<n.children.length; j++){
                Node childNode = nodes[n.children[j]];
                // 递归调用，恢复子节点的秘密值
                if (nodeRecover(nodes, childNode, atts, bp)){
                    System.out.println("The node with index " + n.children[j] + " is sarisfied!");
                    validChildrenList.add(valueOf(n.children[j]));
                    // 如果满足条件的子节点个数已经达到门限值，则跳出循环，不再计算剩余的节点
                    if (validChildrenList.size() == n.gate[0]) {
                        n.valid = true;
                        break;
                    }
                }
                else {
                    System.out.println("The node with index " + n.children[j] + " is not sarisfied!");
                }
            }
            // 如果可恢复的子节点个数等于门限值，则利用子节点的秘密分片恢复当前节点的秘密。
            if (validChildrenList.size() == n.gate[0]){
                validChildren = validChildrenList.stream().mapToInt(i->i).toArray();
                // 利用拉格朗日差值恢复秘密
                // 注意，此处是在指数因子上做拉格朗日差值
                Element secret = bp.getGT().newOneElement().getImmutable();
                for (int i : validChildren) {
                    Element delta = lagrange(i, validChildren, 0, bp);  //计算拉个朗日插值因子
                    secret = secret.mul(nodes[i].secretShare.duplicate().powZn(delta)); //基于拉格朗日因子进行指数运算，然后连乘
                }
                n.secretShare = secret;
            }
        }
        else {
            // 判断叶子节点的属性值是否属于属性列表
            // 判断一个元素是否属于数组，注意String类型和int类型的判断方式不同
            if (Arrays.stream(atts).boxed().collect(Collectors.toList()).contains(n.att)){
                n.valid = true;
            }
        }
        return n.valid;
    }

    public static void storePropToFile(Properties prop, String fileName){
        try(FileOutputStream out = new FileOutputStream(fileName)){
            prop.store(out, null);
        }
        catch (IOException e) {
            e.printStackTrace();
            System.out.println(fileName + " save failed!");
            System.exit(-1);
        }
    }

    public static Properties loadPropFromFile(String fileName) {
        Properties prop = new Properties();
        try (FileInputStream in = new FileInputStream(fileName)){
            prop.load(in);
        }
        catch (IOException e){
            e.printStackTrace();
            System.out.println(fileName + " load failed!");
            System.exit(-1);
        }
        return prop;
    }


    public static void main(String[] args) throws Exception {
        int U = 20;
        int[] messageAttList = {1, 2, 3};
        Node[] accessTree = new Node[7];
        accessTree[0] = new Node(new int[]{2,3}, new int[]{1,2,3});
        accessTree[1] = new Node(1);
        accessTree[2] = new Node(new int[]{2,3}, new int[]{4,5,6});
        accessTree[3] = new Node(5);
        accessTree[4] = new Node(2);
        accessTree[5] = new Node(3);
        accessTree[6] = new Node(4);

//        int[] messageAttList = {1};
//        Node[] accessTree = new Node[3];
//        accessTree[0] = new Node(new int[]{2,2}, new int[]{1,2});
//        accessTree[1] = new Node(1);
//        accessTree[2] = new Node(2);

        String dir = "data/";
        String pairingParametersFileName = "a.properties";
        String pkFileName = dir + "pk.properties";
        String mskFileName = dir + "msk.properties";
        String skFileName = dir + "sk.properties";
        String ctFileName = dir + "ct.properties";

        setup(pairingParametersFileName, U, pkFileName, mskFileName);

        keygen(pairingParametersFileName, accessTree, pkFileName, mskFileName, skFileName);

        Element message = PairingFactory.getPairing(pairingParametersFileName).getGT().newRandomElement().getImmutable();
//        System.out.println("明文消息:" + message);
        encrypt(pairingParametersFileName, message, messageAttList, pkFileName, ctFileName);

        // 模拟实际情况，将所有的节点的secretShare置为null
        for (Node node : accessTree) {
            node.secretShare = null;
        }

        Element res = decrypt(pairingParametersFileName, accessTree, pkFileName, ctFileName, skFileName);
        System.out.println("解密结果:" + res);
        if (message.isEqual(res)) {
            System.out.println("成功解密！");
        }
    }

}
