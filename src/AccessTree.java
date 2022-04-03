import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static java.lang.Integer.valueOf;

public class AccessTree {

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

    //没用递归的秘密共享过程
//    public static void rootShare(Node[] nodes, Element secret, Pairing bp){
//        nodes[0].secretShare = bp.getZr().newElement(10);
//        for (Node node : nodes) {
//            if (!node.isLeaf()) {
//                Element[] coef = randomP(node.gate[1], node.secretShare, bp);
//                for (Element e:coef){
//                    System.out.println(e);
//                }
//                for (int i=0; i<node.children.length; i++ ){
//                    nodes[node.children[i]].secretShare = qx(bp.getZr().newElement(node.children[i]), coef, bp);
//                }
//            }
//        }
//    }

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
                    validChildrenList.add(valueOf(n.children[j]));
                    // 如果满足条件的子节点个数已经达到门限值，则跳出循环，不再计算剩余的节点
                    if (validChildrenList.size() == n.gate[0]) {
                        n.valid = true;
                        break;
                    }
                }
            }
            // 如果可恢复的子节点个数等于门限值，则利用子节点的秘密分片恢复当前节点的秘密。
            if (validChildrenList.size() == n.gate[0]){
                validChildren = validChildrenList.stream().mapToInt(i->i).toArray();
                // 利用拉格朗日差值恢复秘密
                Element secret = bp.getZr().newZeroElement().getImmutable();
                for (int i : validChildren) {
                    Element delta = lagrange(i, validChildren, 0, bp);  //计算拉个朗日插值因子
                    secret = secret.add(nodes[i].secretShare.duplicate().mul(delta));
                }
                n.secretShare = secret;
            }
        }
        else {
            if (Arrays.stream(atts).boxed().collect(Collectors.toList()).contains(n.att)){
                n.valid = true;
            }
        }
        return n.valid;
    }


    public static void main(String[] args) {

        Pairing bp = PairingFactory.getPairing("a.properties");

        Node[] nodes = new Node[7];
        nodes[0] = new Node(new int[]{2,3}, new int[]{1,2,3});
        nodes[1] = new Node(1);
        nodes[2] = new Node(new int[]{2,3}, new int[]{4,5,6});
        nodes[3] = new Node(5);
        nodes[4] = new Node(2);
        nodes[5] = new Node(3);
        nodes[6] = new Node(4);

        nodes[0].secretShare = bp.getZr().newElement(10);
        nodeShare(nodes, nodes[0], bp);
        for (Node node:nodes){
            System.out.println(node);
            System.out.println(node.secretShare);
        }
        System.out.println("________________________________________________");
        System.out.println("________________________________________________");

        for (Node node:nodes){
            if (!node.isLeaf()){
                node.secretShare = null;
            }
            System.out.println(node);
            System.out.println(node.secretShare);
        }

        int[] AttList = {1, 2, 3, 5};
        boolean res = nodeRecover(nodes, nodes[0], AttList, bp);

        System.out.println("++++++++++++++++++++++++++++++++++++++++++++++++");
        System.out.println("++++++++++++++++++++++++++++++++++++++++++++++++");

        for (Node node:nodes){
            System.out.println(node);
            System.out.println(node.secretShare);
        }
        System.out.println(res);
   }
}
